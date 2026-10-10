//! VM 稳定标识（P0 冻结规格）
//! SMBIOS UUID 优先（PVE 写入 VM 配置，跨迁移稳定），node+VMID 兜底。
//! 同步时检测 VMID 复用串扰（同 VMID 不同 UUID）→ 旧绑定置 stale 并重建绑定，
//! 全过程写入 vm_identity_events 与审计日志；VM 消失标记 deleted（策略保留待回收）。
//! 防呆：远端输出必须带完整结束标记才入库，写库段包裹在事务中。
use serde::Serialize;
use std::sync::Arc;

use crate::AppState;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Vm {
    pub id: i64,
    pub host_id: i64,
    pub vmid: i64,
    pub smbios_uuid: Option<String>,
    pub name: Option<String>,
    pub status: String,
    pub first_seen: Option<chrono::NaiveDateTime>,
    pub last_seen: Option<chrono::NaiveDateTime>,
    pub deleted_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Serialize)]
pub struct SyncReport {
    pub total: usize,
    pub new: usize,
    pub rebound: usize,
    pub deleted: usize,
}

/// 同步一台主机的 VM 清单与 SMBIOS UUID
pub async fn sync_vms(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<SyncReport> {
    let host = crate::db::get_host(&state.db, host_id).await?;
    if host.host_key_status.as_deref() != Some("confirmed") {
        return Err(anyhow::anyhow!("主机密钥指纹未确认"));
    }
    let auth = crate::deploy::SshAuth::from_host(
        host.password_encrypted.as_deref(),
        host.ssh_key_encrypted.as_deref(),
        &state.master_key,
    )?;

    // 单次 SSH 抓取全部 VM 的 vmid|uuid|name，末尾哨兵行标记输出完整。
    // qm list 失败时整条命令非零退出且不输出哨兵（严格模式 SSH 报错 + 缺哨兵双保险），
    // 避免把现有 active VM 误标 deleted。
    let cmd = "list=$(qm list) || exit 1; \
        for vm in $(printf '%s\\n' \"$list\" | awk 'NR>1{print $1}'); do \
        cfg=$(qm config \"$vm\" 2>/dev/null); \
        uuid=$(printf '%s' \"$cfg\" | grep -oE 'uuid=[0-9a-fA-F-]{36}' | head -1 | cut -d= -f2); \
        name=$(printf '%s' \"$cfg\" | sed -n 's/^name: //p'); \
        echo \"$vm|$uuid|$name\"; done; echo __SYNC_DONE__";

    let out = crate::deploy::ssh_exec_kh(
        &host.host, host.port as u16, &host.username, &auth, cmd,
        Some(&state.known_hosts_path),
    ).await?;
    if !out.lines().any(|l| l.trim() == "__SYNC_DONE__") {
        return Err(anyhow::anyhow!("VM 清单输出不完整（缺少结束标记），已放弃同步"));
    }

    let mut seen: Vec<(i64, String, String)> = Vec::new();
    for line in out.lines() {
        let mut parts = line.splitn(3, '|');
        let (Some(vmid_s), Some(uuid), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if let Ok(vmid) = vmid_s.trim().parse::<i64>() {
            // UUID 统一小写规范化入库（SQLite 唯一索引区分大小写）
            seen.push((vmid, uuid.trim().to_lowercase(), name.trim().to_string()));
        }
    }

    let mut report = SyncReport { total: seen.len(), new: 0, rebound: 0, deleted: 0 };
    let mut rebind_logs: Vec<String> = Vec::new();

    // 事务：同步要么完整生效要么全部回滚，不留半同步状态
    let mut tx = state.db.begin().await?;

    for (vmid, uuid, name) in &seen {
        let uuid_opt = if uuid.is_empty() { None } else { Some(uuid.clone()) };
        let active = sqlx::query_as::<_, Vm>(
            "SELECT * FROM vms WHERE host_id=? AND vmid=? AND status='active'"
        )
        .bind(host_id).bind(vmid)
        .fetch_optional(&mut *tx)
        .await?;

        match active {
            Some(row) => {
                match (&row.smbios_uuid, &uuid_opt) {
                    // 两端 UUID 均非空且不一致：VMID 复用串扰，旧绑定失效重建
                    (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b) => {
                        sqlx::query("UPDATE vms SET status='stale', deleted_at=CURRENT_TIMESTAMP WHERE id=?")
                            .bind(row.id).execute(&mut *tx).await?;
                        insert_vm(&mut tx, host_id, *vmid, uuid_opt.clone(), name).await?;
                        record_event(&mut tx, host_id, *vmid, row.smbios_uuid.as_deref(), uuid_opt.as_deref(), "rebind").await;
                        rebind_logs.push(format!("vmid={} old_uuid={:?} new_uuid={:?}", vmid, row.smbios_uuid, uuid_opt));
                        report.rebound += 1;
                    }
                    // 一端无 UUID：视为同一台（node+VMID 兜底），有 UUID 则补录
                    (old, new) => {
                        let fill = old.is_none() && new.is_some();
                        if fill {
                            sqlx::query("UPDATE vms SET smbios_uuid=?, name=?, last_seen=CURRENT_TIMESTAMP WHERE id=?")
                                .bind(new).bind(name).bind(row.id).execute(&mut *tx).await?;
                            record_event(&mut tx, host_id, *vmid, None, new.as_deref(), "uuid_backfill").await;
                        } else {
                            sqlx::query("UPDATE vms SET name=?, last_seen=CURRENT_TIMESTAMP WHERE id=?")
                                .bind(name).bind(row.id).execute(&mut *tx).await?;
                        }
                    }
                }
            }
            None => {
                insert_vm(&mut tx, host_id, *vmid, uuid_opt.clone(), name).await?;
                record_event(&mut tx, host_id, *vmid, None, uuid_opt.as_deref(), "discovered").await;
                report.new += 1;
            }
        }
    }

    // 未出现在清单中的 active VM → 标记删除（策略与历史保留，状态置 deleted 待回收）
    let actives = sqlx::query_as::<_, Vm>("SELECT * FROM vms WHERE host_id=? AND status='active'")
        .bind(host_id).fetch_all(&mut *tx).await?;
    let seen_ids: std::collections::HashSet<i64> = seen.iter().map(|(v, _, _)| *v).collect();
    for row in actives {
        if !seen_ids.contains(&row.vmid) {
            sqlx::query("UPDATE vms SET status='deleted', deleted_at=CURRENT_TIMESTAMP WHERE id=?")
                .bind(row.id).execute(&mut *tx).await?;
            record_event(&mut tx, host_id, row.vmid, row.smbios_uuid.as_deref(), None, "deleted").await;
            report.deleted += 1;
        }
    }

    tx.commit().await?;

    for detail in rebind_logs {
        crate::audit::log(&state.db, "system", "vm.rebind", Some("host"), Some(host_id), Some(&detail), None).await;
    }

    Ok(report)
}

async fn insert_vm(conn: &mut sqlx::SqliteConnection, host_id: i64, vmid: i64, uuid: Option<String>, name: &str) -> anyhow::Result<()> {
    // UUID 已被同主机另一 VMID 的活动绑定占用（克隆/手工复制配置）→ 旧绑定失效，避免撞上唯一索引
    // COLLATE NOCASE：兼容规范化前可能残留的大小写混合数据
    if let Some(u) = &uuid {
        let r = sqlx::query("UPDATE vms SET status='stale', deleted_at=CURRENT_TIMESTAMP WHERE host_id=? AND smbios_uuid=? COLLATE NOCASE AND status='active'")
            .bind(host_id).bind(u).execute(&mut *conn).await?;
        if r.rows_affected() > 0 {
            record_event(conn, host_id, vmid, Some(u), Some(u), "uuid_conflict").await;
        }
    }
    sqlx::query("INSERT INTO vms (host_id, vmid, smbios_uuid, name) VALUES (?, ?, ?, ?)")
        .bind(host_id).bind(vmid).bind(&uuid).bind(name).execute(conn).await?;
    Ok(())
}

async fn record_event(conn: &mut sqlx::SqliteConnection, host_id: i64, vmid: i64, old_uuid: Option<&str>, new_uuid: Option<&str>, reason: &str) {
    let _ = sqlx::query(
        "INSERT INTO vm_identity_events (host_id, vmid, old_uuid, new_uuid, reason) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(host_id).bind(vmid).bind(old_uuid).bind(new_uuid).bind(reason)
    .execute(conn).await;
}

/// 解析 VM 稳定标识：优先 UUID 命中 active 绑定，否则 node+VMID 兜底
/// （框架 API，P1 起管控/限速模块关联策略时使用）
#[allow(dead_code)]
pub async fn resolve_vm(pool: &sqlx::SqlitePool, host_id: i64, vmid: i64) -> anyhow::Result<Option<Vm>> {
    Ok(sqlx::query_as::<_, Vm>(
        "SELECT * FROM vms WHERE host_id=? AND vmid=? AND status='active'"
    )
    .bind(host_id).bind(vmid)
    .fetch_optional(pool)
    .await?)
}
