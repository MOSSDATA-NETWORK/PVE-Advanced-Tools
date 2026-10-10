//! P3 带宽 QoS 核心：vmqos 契约（schema v2）快照生成、接入 token 管理、
//! 事件去重、节点状态推断、档位模板校验与 config.toml 渲染。
//!
//! 契约基线：vmqos v0.0.6 docs/vmqos-database-api-contract.md。
//! 已知偏差（经双签与用户确认）：
//! - 事件无单调序号（vmqos 协议无此字段），按内容哈希 + 时间窗近似去重
//! - 档位模板为节点级（vmqos [stages] 全局单份，零改动下无法按 VM 分配）
//! - fresh/degraded/stale 为平台推断值（vmqos 无心跳端点）
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::AppState;

/// 事件去重窗口（秒）
pub const DEDUP_WINDOW_SECS: i64 = 120;
/// 快照拉取超时阈值（秒）：vmqos 默认 60s 刷新，超过 5 分钟未拉取视为 stale
pub const SNAPSHOT_STALE_SECS: i64 = 300;

/// 生成接入 token（32 字节随机 hex）
pub fn gen_token() -> String {
    crate::crypto::generate_token()
}

/// token 哈希（sha256 hex）：DB 校验用，不存明文索引
pub fn token_hash(token: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(token.as_bytes()))
}

/// 签发/轮换 token：新 token 为 active，旧 active 转 retiring（重叠期内仍可校验），
/// 待配置下发任务成功后由 revoke_retiring 撤销。返回明文（仅此一次可见）。
pub async fn issue_token(
    pool: &SqlitePool,
    master_key: &[u8],
    host_id: i64,
    purpose: &str,
) -> anyhow::Result<String> {
    let token = gen_token();
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE qos_tokens SET status='retiring' WHERE host_id=? AND purpose=? AND status='active'")
        .bind(host_id).bind(purpose).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO qos_tokens (host_id, purpose, token_hash, token_enc, status) VALUES (?, ?, ?, ?, 'active')"
    )
    .bind(host_id).bind(purpose).bind(token_hash(&token))
    .bind(crate::crypto::encrypt(&token, master_key))
    .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(token)
}

/// 校验 token：active 与 retiring（轮换重叠期）均接受；命中更新 last_used_at
pub async fn verify_token(pool: &SqlitePool, purpose: &str, token: &str) -> Option<i64> {
    if token.is_empty() {
        return None;
    }
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT host_id, id FROM qos_tokens WHERE token_hash=? AND purpose=? AND status IN ('active','retiring')"
    )
    .bind(token_hash(token)).bind(purpose)
    .fetch_optional(pool).await.ok()?;
    let (host_id, token_id) = row?;
    let _ = sqlx::query("UPDATE qos_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(token_id).execute(pool).await;
    Some(host_id)
}

/// 撤销 retiring 状态的 token（配置下发成功后调用）
pub async fn revoke_retiring(pool: &SqlitePool, host_id: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE qos_tokens SET status='revoked' WHERE host_id=? AND status='retiring'")
        .bind(host_id).execute(pool).await?;
    Ok(())
}

/// 取主机当前 active token 明文（渲染配置用）
pub async fn active_token_plain(pool: &SqlitePool, master_key: &[u8], host_id: i64, purpose: &str) -> anyhow::Result<String> {
    let enc: Option<(String,)> = sqlx::query_as(
        "SELECT token_enc FROM qos_tokens WHERE host_id=? AND purpose=? AND status='active'"
    )
    .bind(host_id).bind(purpose).fetch_optional(pool).await?;
    let (enc,) = enc.ok_or_else(|| anyhow::anyhow!("主机 {} 缺少 {} token，请先在 QoS 页签发", host_id, purpose))?;
    crate::crypto::decrypt(&enc, master_key)
}

/// IPv4 规范化比较：host.host 可能是主机名；node_ip 必须是合法 IPv4 且与主机地址一致
pub fn node_ip_matches(host_addr: &str, node_ip: &str) -> bool {
    let Ok(ip) = node_ip.trim().parse::<std::net::Ipv4Addr>() else { return false };
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    match host_addr.trim().parse::<std::net::Ipv4Addr>() {
        Ok(h) => h == ip,
        Err(_) => host_addr.trim() == node_ip.trim(),
    }
}

/// 按契约 §2.2 生成 schema v2 快照
pub async fn build_snapshot(state: &Arc<AppState>, host: &crate::db::Host) -> anyhow::Result<Value> {
    let policies = sqlx::query_as::<_, (i64, String, String, i64, Option<i64>)>(
        "SELECT id, vmid, origin, initial_mbps, net2_mbps FROM qos_policies WHERE host_id=? AND enabled=1 ORDER BY id"
    )
    .bind(host.id).fetch_all(&state.db).await?;

    let cluster_id: i64 = sqlx::query_scalar("SELECT COALESCE(cluster_id, 1) FROM hosts WHERE id=?")
        .bind(host.id).fetch_one(&state.db).await?;

    let mut domestic: Vec<Value> = Vec::new();
    let mut intl: Vec<Value> = Vec::new();
    for (pid, vmid, origin, mbps, net2) in policies {
        let Ok(vmid_num) = vmid.parse::<u32>() else { continue };
        let mut ports = vec![json!({"name": "net0", "initial_mbps": mbps, "mac": Value::Null})];
        // net2 为国内专线最终值（契约 §2.2）
        if origin == "domestic" {
            if let Some(n2) = net2 {
                ports.push(json!({"name": "net2", "initial_mbps": n2, "mac": Value::Null}));
            }
        }
        let svc = json!({
            "service_id": pid,
            "vmid": vmid_num,
            "cluster_id": cluster_id,
            "node": host.name,
            "origin": origin,
            "report_target": if origin == "domestic" {
                json!({"type": "domestic"})
            } else {
                json!({"type": "international", "cluster_id": cluster_id})
            },
            "ports": ports,
        });
        if origin == "domestic" { domestic.push(svc) } else { intl.push(svc) }
    }

    let src = |services: Vec<Value>, intl: bool| {
        if intl && services.is_empty() {
            // 国际站关闭形状（契约 §2.2）
            json!({
                "status": "disabled", "complete": true,
                "counts": {"services": 0, "skipped": {"cluster_mismatch": 0, "below_min_vmid": 0, "high_traffic": 0, "vmid_whitelist": 0}},
                "services": []
            })
        } else {
            let skipped = if intl {
                json!({"cluster_mismatch": 0, "below_min_vmid": 0, "high_traffic": 0, "vmid_whitelist": 0})
            } else {
                json!({"cluster_mismatch": 0, "below_min_vmid": 0, "flows_zero": 0, "vmid_whitelist": 0})
            };
            json!({
                "status": "ok", "complete": true,
                "counts": {"services": services.len(), "skipped": skipped},
                "services": services
            })
        }
    };

    Ok(json!({
        "schema_version": 2,
        "snapshot_id": uuid::Uuid::new_v4().simple().to_string(),
        "generated_at": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "complete": true,
        "node_ip": host.host,
        "clusters": [cluster_id],
        "sources": {
            "domestic": src(domestic, false),
            "international": src(intl, true),
        }
    }))
}

/// 记录限速事件：内容哈希 + 时间窗去重（vmqos 上报无序号，无法严格一次）。
/// 返回是否真正写入（false = 窗口内重复）。
pub async fn record_event(
    state: &Arc<AppState>,
    host_id: i64,
    origin: &str,
    vmid: &str,
    stage: i64,
    limit_mbps: Option<f64>,
) -> anyhow::Result<bool> {
    let dedup = token_hash(&format!("{}|{}|{}|{}|{:.2}", host_id, origin, vmid, stage, limit_mbps.unwrap_or(0.0)));
    // BEGIN IMMEDIATE 立即取写锁：查重+写入同一事务，并发上报不会产生重复行
    let mut conn = state.db.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let dup: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM qos_events WHERE dedup_hash=? AND reported_at > datetime('now', ?)"
    )
    .bind(&dedup).bind(format!("-{} seconds", DEDUP_WINDOW_SECS))
    .fetch_one(&mut *conn).await?;
    if dup > 0 {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        touch_report(&state.db, host_id).await;
        return Ok(false);
    }
    sqlx::query("INSERT INTO qos_events (host_id, origin, vmid, stage, limit_mbps, dedup_hash) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(host_id).bind(origin).bind(vmid).bind(stage).bind(limit_mbps).bind(&dedup)
        .execute(&mut *conn).await?;
    if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Err(e.into());
    }
    // stage=0 为删除语义：档位归零但保留状态行（核验端点按 active:false 回应）
    sqlx::query(
        "INSERT INTO qos_vm_state (host_id, origin, vmid, current_stage, current_limit, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP) \
         ON CONFLICT(host_id, vmid, origin) DO UPDATE SET current_stage=excluded.current_stage, current_limit=excluded.current_limit, updated_at=CURRENT_TIMESTAMP"
    )
    .bind(host_id).bind(origin).bind(vmid).bind(stage).bind(limit_mbps)
    .execute(&state.db).await?;
    touch_report(&state.db, host_id).await;
    Ok(true)
}

async fn touch_report(pool: &SqlitePool, host_id: i64) {
    let _ = sqlx::query(
        "INSERT INTO qos_node_status (host_id, last_report_at) VALUES (?, CURRENT_TIMESTAMP) \
         ON CONFLICT(host_id) DO UPDATE SET last_report_at=CURRENT_TIMESTAMP"
    ).bind(host_id).execute(pool).await;
}

/// 快照拉取回写（节点心跳证据）+ 归档最新快照
pub async fn record_snapshot_pull(pool: &SqlitePool, host_id: i64, snapshot: &Value) {
    let _ = sqlx::query(
        "INSERT INTO qos_node_status (host_id, last_snapshot_at) VALUES (?, CURRENT_TIMESTAMP) \
         ON CONFLICT(host_id) DO UPDATE SET last_snapshot_at=CURRENT_TIMESTAMP, last_error=NULL"
    ).bind(host_id).execute(pool).await;
    let sid = snapshot.get("snapshot_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let _ = sqlx::query(
        "INSERT INTO qos_snapshots (host_id, snapshot_id, pulled_at, raw_json) VALUES (?, ?, CURRENT_TIMESTAMP, ?) \
         ON CONFLICT(host_id) DO UPDATE SET snapshot_id=excluded.snapshot_id, pulled_at=CURRENT_TIMESTAMP, raw_json=excluded.raw_json"
    ).bind(host_id).bind(sid).bind(snapshot.to_string()).execute(pool).await;
}

/// 节点鉴权/地址异常记录（degraded 推断证据）
pub async fn record_node_error(pool: &SqlitePool, host_id: i64, msg: &str) {
    let _ = sqlx::query(
        "INSERT INTO qos_node_status (host_id, last_error) VALUES (?, ?) \
         ON CONFLICT(host_id) DO UPDATE SET last_error=excluded.last_error"
    ).bind(host_id).bind(msg).execute(pool).await;
}

/// 节点状态推断：fresh = 快照拉取在阈值内且无近期错误；degraded = 在拉但有错误；stale = 超阈值未拉取
pub fn infer_node_status(last_snapshot: Option<chrono::NaiveDateTime>, last_error: &Option<String>) -> &'static str {
    match last_snapshot {
        Some(t) if (chrono::Utc::now().naive_utc() - t).num_seconds() <= SNAPSHOT_STALE_SECS => {
            if last_error.is_some() { "degraded" } else { "fresh" }
        }
        _ => "stale",
    }
}

/// 档位模板校验（下发前）：limits 含 0 档=1.0、比例 (0,1] 且随档位不增、阈值 (0,1]、升档规则引用已定义档位
pub fn validate_template(config: &Value) -> Result<(), String> {
    let ratio = config.get("high_usage_ratio").and_then(|v| v.as_f64())
        .ok_or("缺少 high_usage_ratio")?;
    if ratio <= 0.0 || ratio > 1.0 {
        return Err("high_usage_ratio 须在 (0,1]".into());
    }
    let limits = config.get("limits").and_then(|v| v.as_object()).ok_or("缺少 limits")?;
    if limits.is_empty() {
        return Err("limits 不能为空".into());
    }
    let mut stages: Vec<(u8, f64)> = Vec::new();
    for (k, v) in limits {
        let s: u8 = k.parse().map_err(|_| format!("limits 键 {} 非数字档位", k))?;
        let r = v.as_f64().ok_or(format!("档位 {} 比例非数字", k))?;
        if r <= 0.0 || r > 1.0 {
            return Err(format!("档位 {} 比例须在 (0,1]", k));
        }
        stages.push((s, r));
    }
    stages.sort_by(|a, b| a.0.cmp(&b.0));
    if stages.first().map(|(s, r)| (*s, *r)) != Some((0, 1.0)) {
        return Err("limits 必须含 0 档且比例为 1.0".into());
    }
    for w in stages.windows(2) {
        if w[1].1 > w[0].1 {
            return Err(format!("档位 {} 比例不得高于档位 {}", w[1].0, w[0].0));
        }
    }
    let max_stage = stages.last().map(|(s, _)| *s).unwrap_or(0);
    if let Some(cap) = config.get("stage_cap").and_then(|v| v.as_u64()) {
        if cap > max_stage as u64 {
            return Err(format!("stage_cap {} 超过已定义最大档位 {}", cap, max_stage));
        }
    }
    if let Some(recover) = config.get("recover_rules") {
        for key in ["step", "full"] {
            if let Some(r) = recover.get(key) {
                if let Some(ratio) = r.get("ratio").and_then(|v| v.as_f64()) {
                    if ratio <= 0.0 || ratio > 1.0 {
                        return Err(format!("recover_rules.{}.ratio 须在 (0,1]", key));
                    }
                }
                for sk in ["seconds", "ratio_seconds"] {
                    if let Some(sec) = r.get(sk).and_then(|v| v.as_f64()) {
                        if sec <= 0.0 {
                            return Err(format!("recover_rules.{}.{} 须为正", key, sk));
                        }
                    }
                }
            }
        }
    }
    if let Some(rules) = config.get("raise_rules").and_then(|v| v.as_array()) {
        for r in rules {
            let s = r.get("stage").and_then(|v| v.as_u64()).ok_or("raise_rules 缺 stage")?;
            if !stages.iter().any(|(ls, _)| *ls as u64 == s) {
                return Err(format!("raise_rules 引用了未定义档位 {}", s));
            }
            let sec = r.get("seconds").and_then(|v| v.as_f64()).ok_or("raise_rules 缺 seconds")?;
            if sec <= 0.0 {
                return Err("raise_rules seconds 须为正".into());
            }
        }
    }
    Ok(())
}

/// 渲染节点 config.toml：接入地址/token + 模板 [stages] + 固定默认段
pub fn render_config(
    snapshot_url: &str,
    snapshot_token: &str,
    report_base: &str,
    report_token: &str,
    intl_url: &str,
    intl_token: &str,
    template: &Value,
) -> anyhow::Result<String> {
    // TOML 注入防护：插值进字符串字面量的入参不得含引号/反斜杠/控制字符
    for (name, v) in [("snapshot_url", snapshot_url), ("snapshot_token", snapshot_token),
                      ("report_base", report_base), ("report_token", report_token),
                      ("intl_url", intl_url), ("intl_token", intl_token)] {
        if v.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
            return Err(anyhow::anyhow!("{} 含非法字符（引号/反斜杠/控制字符）", name));
        }
    }
    let ratio = template.get("high_usage_ratio").and_then(|v| v.as_f64()).unwrap_or(0.8);
    let mut limits = String::new();
    if let Some(obj) = template.get("limits").and_then(|v| v.as_object()) {
        let mut entries: Vec<(&String, &Value)> = obj.iter().collect();
        entries.sort_by_key(|(k, _)| k.parse::<u8>().unwrap_or(0));
        for (k, v) in entries {
            limits.push_str(&format!("{} = {}\n", k, v));
        }
    }
    let mut raise = String::new();
    if let Some(rules) = template.get("raise_rules").and_then(|v| v.as_array()) {
        for r in rules {
            raise.push_str(&format!(
                "\n[[stages.raise_rules]]\nstage = {}\nseconds = {}\n",
                r.get("stage").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("seconds").and_then(|v| v.as_f64()).unwrap_or(150.0)
            ));
        }
    }
    let recover = template.get("recover_rules").cloned().unwrap_or_else(|| json!({
        "step": {"ratio": 0.5, "seconds": 300.0},
        "full": {"ratio": 0.3, "seconds": 1200.0, "ratio_seconds": 600.0}
    }));
    let r_step = recover.get("step").cloned().unwrap_or(json!({}));
    let r_full = recover.get("full").cloned().unwrap_or(json!({}));

    Ok(format!(r#"# 由 PVE-Advanced-Tools 平台渲染下发，请勿在节点手工编辑
[api]
url = "{snapshot_url}"
token = "{snapshot_token}"
timeout_secs = 45

[qos]
api_url = "{report_base}"
api_token = "{report_token}"

[international_qos]
api_url = "{intl_url}"
api_token = "{intl_token}"

[sampling]
sample_interval_secs = 5
api_refresh_interval_secs = 60

[stages]
high_usage_ratio = {ratio}

[stages.limits]
{limits}{raise}
[stages.recover_rules.step]
ratio = {step_ratio}
seconds = {step_secs}

[stages.recover_rules.full]
ratio = {full_ratio}
seconds = {full_secs}
ratio_seconds = {full_ratio_secs}

[peak]
stage_cap = {stage_cap}
decay = 0.7
recover = 0.02
min_ratio = 0.05

[network]
template = "tap{{vmid}}i{{index}}"
cluster_iface = "vmbr0"

[network.port_index]
net0 = 0
net1 = 1
net2 = 2

[paths]
sys_class_net = "/sys/class/net"
pve_qemu_conf_dir = "/etc/pve/qemu-server"
snapshot_file = "/var/lib/vmqos/api-snapshot.json"

[logging]
level = "info"

[runtime]
flush_redis_on_start = false
worker_pool_size = 10
qm_timeout_secs = 30
"#,
        snapshot_url = snapshot_url,
        snapshot_token = snapshot_token,
        report_base = report_base,
        report_token = report_token,
        intl_url = intl_url,
        intl_token = intl_token,
        ratio = ratio,
        limits = limits,
        raise = raise,
        step_ratio = r_step.get("ratio").and_then(|v| v.as_f64()).unwrap_or(0.5),
        step_secs = r_step.get("seconds").and_then(|v| v.as_f64()).unwrap_or(300.0),
        full_ratio = r_full.get("ratio").and_then(|v| v.as_f64()).unwrap_or(0.3),
        full_secs = r_full.get("seconds").and_then(|v| v.as_f64()).unwrap_or(1200.0),
        full_ratio_secs = r_full.get("ratio_seconds").and_then(|v| v.as_f64()).unwrap_or(600.0),
        stage_cap = template.get("stage_cap").and_then(|v| v.as_u64()).unwrap_or(6),
    ))
}

/// 平台内置默认模板（与 vmqos config.toml 默认 [stages] 一致）
pub fn builtin_template() -> Value {
    json!({
        "high_usage_ratio": 0.8,
        "limits": {"0": 1.0, "1": 0.85, "2": 0.70, "3": 0.55, "4": 0.40, "5": 0.30, "6": 0.20, "7": 0.12, "8": 0.07, "9": 0.025},
        "raise_rules": [
            {"stage": 1, "seconds": 600.0},
            {"stage": 2, "seconds": 150.0}, {"stage": 3, "seconds": 150.0},
            {"stage": 4, "seconds": 150.0}, {"stage": 5, "seconds": 150.0},
            {"stage": 6, "seconds": 150.0}, {"stage": 7, "seconds": 150.0},
            {"stage": 8, "seconds": 150.0}, {"stage": 9, "seconds": 150.0}
        ],
        "recover_rules": {
            "step": {"ratio": 0.5, "seconds": 300.0},
            "full": {"ratio": 0.3, "seconds": 1200.0, "ratio_seconds": 600.0}
        },
        "stage_cap": 6
    })
}
