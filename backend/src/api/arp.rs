//! M4 ARP 降噪 API：运行模式（passive/static）、灰度白名单、static 映射表
//! 全部变更经任务框架下发；ARP 类任务一律 fail-open（不断网优先）
use axum::{extract::{Path, State}, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

fn valid_ipv4(s: &str) -> bool {
    s.split('.').count() == 4
        && s.split('.').all(|p| p.parse::<u8>().is_ok())
}

/// PVE VMID 合法范围
fn valid_vmid(v: i64) -> bool {
    (1..=999_999_999).contains(&v)
}

/// 网卡序号范围（PVE net0-net31）
fn valid_nic(n: i64) -> bool {
    (0..=31).contains(&n)
}

// ---- 模式管理 ----

pub async fn list_modes(State(state): State<Arc<AppState>>) -> Json<Value> {
    let r = sqlx::query_as::<_, (i64, String, Option<chrono::NaiveDateTime>)>(
        "SELECT host_id, mode, updated_at FROM arp_mode"
    ).fetch_all(&state.db).await;
    match r {
        Ok(rows) => Json(json!({"ok": true, "data": rows.iter().map(|r| json!({
            "host_id": r.0, "mode": r.1, "updated_at": r.2
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct ModeRequest {
    pub mode: String,
}

/// 安装或切换模式（生成对应任务）
pub async fn set_mode(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(host_id): Path<i64>,
    Json(body): Json<ModeRequest>,
) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    if body.mode != "passive" && body.mode != "static" {
        return Json(json!({"ok": false, "error": "模式必须为 passive 或 static"}));
    }

    // 已装另一模式 → 单任务原子切换（先卸旧再装新，避免两任务竞争主机锁）
    let current: Option<(String,)> = sqlx::query_as("SELECT mode FROM arp_mode WHERE host_id = ?")
        .bind(host_id).fetch_optional(&state.db).await.unwrap_or(None);
    if let Some((m,)) = current {
        if m != body.mode {
            match crate::tasks::arpfilter_switch(&state, host_id, &m, &body.mode).await {
                Ok(spec) => {
                    return match crate::jobs::create_and_enqueue(&state, host_id, spec, &actor).await {
                        Ok(id) => {
                            crate::audit::log(&state.db, &actor, "arp.switch_mode", Some("host"), Some(host_id),
                                Some(&format!("{} → {}", m, body.mode)), None).await;
                            Json(json!({"ok": true, "job_id": id}))
                        }
                        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
                    };
                }
                Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
            }
        }
        return Json(json!({"ok": true, "message": "该模式已在运行"}));
    }

    match crate::tasks::arpfilter_install(&state, host_id, &body.mode).await {
        Ok(spec) => match crate::jobs::create_and_enqueue(&state, host_id, spec, &actor).await {
            Ok(id) => {
                crate::audit::log(&state.db, &actor, "arp.set_mode", Some("host"), Some(host_id),
                    Some(&body.mode), None).await;
                Json(json!({"ok": true, "job_id": id}))
            }
            Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
        },
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 卸载（停用降噪）
pub async fn uninstall(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    let current: Option<(String,)> = sqlx::query_as("SELECT mode FROM arp_mode WHERE host_id = ?")
        .bind(host_id).fetch_optional(&state.db).await.unwrap_or(None);
    let Some((mode,)) = current else {
        return Json(json!({"ok": false, "error": "该主机未安装 arpfilter"}));
    };
    let spec = crate::tasks::arpfilter_uninstall(&mode);
    match crate::jobs::create_and_enqueue(&state, host_id, spec, &actor).await {
        Ok(id) => {
            crate::audit::log(&state.db, &actor, "arp.uninstall", Some("host"), Some(host_id), None, None).await;
            Json(json!({"ok": true, "job_id": id}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ---- 灰度白名单 ----

#[derive(Deserialize)]
pub struct WhitelistEntry {
    pub host_id: i64,
    pub vmid: i64,
}

pub async fn whitelist_add(State(state): State<Arc<AppState>>, Json(body): Json<WhitelistEntry>) -> Json<Value> {
    if !valid_vmid(body.vmid) {
        return Json(json!({"ok": false, "error": "VMID 无效"}));
    }
    let r = sqlx::query("INSERT OR IGNORE INTO arp_whitelist (host_id, vmid) VALUES (?, ?)")
        .bind(body.host_id).bind(body.vmid).execute(&state.db).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn whitelist_del(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let r = sqlx::query("DELETE FROM arp_whitelist WHERE id = ?").bind(id).execute(&state.db).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn whitelist_list(State(state): State<Arc<AppState>>, Path(host_id): Path<i64>) -> Json<Value> {
    let r = sqlx::query_as::<_, (i64, i64)>("SELECT id, vmid FROM arp_whitelist WHERE host_id = ? ORDER BY vmid")
        .bind(host_id).fetch_all(&state.db).await;
    match r {
        Ok(rows) => Json(json!({"ok": true, "data": rows.iter().map(|r| json!({"id": r.0, "vmid": r.1})).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ---- static 映射表 ----

#[derive(Deserialize)]
pub struct MapEntry {
    pub host_id: i64,
    pub vmid: i64,
    pub nic: Option<i64>,
    pub ip: String,
}

pub async fn map_add(State(state): State<Arc<AppState>>, Json(body): Json<MapEntry>) -> Json<Value> {
    if !valid_ipv4(&body.ip) {
        return Json(json!({"ok": false, "error": "IPv4 格式无效"}));
    }
    if !valid_vmid(body.vmid) {
        return Json(json!({"ok": false, "error": "VMID 无效"}));
    }
    let nic = body.nic.unwrap_or(0);
    if !valid_nic(nic) {
        return Json(json!({"ok": false, "error": "网卡序号须在 0-31 之间"}));
    }
    let r = sqlx::query("INSERT OR IGNORE INTO arp_maps (host_id, vmid, nic, ip) VALUES (?, ?, ?, ?)")
        .bind(body.host_id).bind(body.vmid).bind(nic).bind(&body.ip).execute(&state.db).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct MapBatch {
    pub host_id: i64,
    /// 每行: vmid,ip 或 vmid,nic,ip
    pub text: String,
}

pub async fn map_import(State(state): State<Arc<AppState>>, Json(body): Json<MapBatch>) -> Json<Value> {
    if body.text.len() > 256 * 1024 || body.text.lines().count() > 5000 {
        return Json(json!({"ok": false, "error": "批量导入过大（限 256KB / 5000 行）"}));
    }
    let mut added = 0;
    let mut skipped = 0;
    for line in body.text.lines() {
        let parts: Vec<&str> = line.split([',', ' ', '\t']).filter(|s| !s.is_empty()).collect();
        let (vmid, nic, ip) = match parts.as_slice() {
            [v, ip] => (v.parse::<i64>(), Ok(0i64), ip.to_string()),
            [v, n, ip] => (v.parse::<i64>(), n.parse::<i64>(), ip.to_string()),
            _ => { skipped += 1; continue; }
        };
        match (vmid, nic) {
            (Ok(v), Ok(n)) if valid_ipv4(&ip) && valid_vmid(v) && valid_nic(n) => {
                match sqlx::query("INSERT OR IGNORE INTO arp_maps (host_id, vmid, nic, ip) VALUES (?, ?, ?, ?)")
                    .bind(body.host_id).bind(v).bind(n).bind(&ip).execute(&state.db).await {
                    Ok(r) if r.rows_affected() > 0 => added += 1,
                    _ => skipped += 1,
                }
            }
            _ => skipped += 1,
        }
    }
    Json(json!({"ok": true, "added": added, "skipped": skipped}))
}

pub async fn map_del(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let r = sqlx::query("DELETE FROM arp_maps WHERE id = ?").bind(id).execute(&state.db).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn map_list(State(state): State<Arc<AppState>>, Path(host_id): Path<i64>) -> Json<Value> {
    let r = sqlx::query_as::<_, (i64, i64, i64, String)>(
        "SELECT id, vmid, nic, ip FROM arp_maps WHERE host_id = ? ORDER BY vmid, nic, ip"
    ).bind(host_id).fetch_all(&state.db).await;
    match r {
        Ok(rows) => Json(json!({"ok": true, "data": rows.iter().map(|r| json!({
            "id": r.0, "vmid": r.1, "nic": r.2, "ip": r.3
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 数据同步（白名单 + 映射 + 触发调和）
pub async fn sync(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    let current: Option<(String,)> = sqlx::query_as("SELECT mode FROM arp_mode WHERE host_id = ?")
        .bind(host_id).fetch_optional(&state.db).await.unwrap_or(None);
    let Some((mode,)) = current else {
        return Json(json!({"ok": false, "error": "该主机未安装 arpfilter"}));
    };
    match crate::tasks::arpfilter_sync(&state, host_id, &mode).await {
        Ok(spec) => match crate::jobs::create_and_enqueue(&state, host_id, spec, &actor).await {
            Ok(id) => {
                crate::audit::log(&state.db, &actor, "arp.sync", Some("host"), Some(host_id), None, None).await;
                Json(json!({"ok": true, "job_id": id}))
            }
            Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
        },
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
