//! M3 出网管控 API：端口封堵 / 域名拦截 / 生效范围 / VM 白名单
//! 列表变更只改库；「下发」动作把当前库状态编译成任务包推到生效主机
use axum::{extract::{Path, State}, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

/// 校验 iptables multiport 格式：数字、逗号、冒号（如 25,465,6880:6999）
/// 约束：端口 1-65535、范围 a:b 须 a<b、单条规则 multiport 最多 15 个元素
fn valid_ports(s: &str) -> bool {
    if s.is_empty() || s.len() > 256 {
        return false;
    }
    let elems: Vec<&str> = s.split(',').collect();
    if elems.len() > 15 {
        return false;
    }
    elems.iter().all(|e| {
        let mut parts = e.split(':');
        let a = parts.next().and_then(|p| p.parse::<u32>().ok());
        let b = parts.next().and_then(|p| p.parse::<u32>().ok());
        if parts.next().is_some() {
            return false;
        }
        match (a, b) {
            (Some(a), Some(b)) => a >= 1 && a < b && b <= 65535,
            (Some(a), None) => (1..=65535).contains(&a),
            _ => false,
        }
    })
}

/// 校验域名格式（iptables string 匹配的注入面很小，但仍收紧）
fn valid_domain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '*')
        && s.contains('.')
}

// ---- 端口封堵列表 ----

pub async fn list_ports(State(state): State<Arc<AppState>>) -> Json<Value> {
    let r = sqlx::query_as::<_, (i64, String, String, bool, bool, Option<chrono::NaiveDateTime>)>(
        "SELECT id, name, ports, enabled, builtin, created_at FROM netguard_ports ORDER BY id"
    ).fetch_all(&state.db).await;
    match r {
        Ok(rows) => Json(json!({"ok": true, "data": rows.iter().map(|r| json!({
            "id": r.0, "name": r.1, "ports": r.2, "enabled": r.3, "builtin": r.4, "created_at": r.5
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct PortEntry {
    pub name: String,
    pub ports: String,
    pub enabled: Option<bool>,
}

pub async fn create_port(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<PortEntry>) -> Json<Value> {
    if !valid_ports(&body.ports) {
        return Json(json!({"ok": false, "error": "端口格式无效（支持 25,465,6880:6999 形式）"}));
    }
    if body.name.is_empty() || body.name.len() > 64 {
        return Json(json!({"ok": false, "error": "名称无效"}));
    }
    let r = sqlx::query("INSERT INTO netguard_ports (name, ports, enabled) VALUES (?, ?, ?)")
        .bind(&body.name).bind(&body.ports).bind(body.enabled.unwrap_or(true))
        .execute(&state.db).await;
    match r {
        Ok(_) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "netguard.port_add", None, None,
                Some(&format!("{} {}", body.name, body.ports)), None).await;
            Json(json!({"ok": true}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn delete_port(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>) -> Json<Value> {
    // 内置模板可禁用但不可删除
    let r = sqlx::query("DELETE FROM netguard_ports WHERE id = ? AND builtin = 0")
        .bind(id).execute(&state.db).await;
    match r {
        Ok(res) if res.rows_affected() > 0 => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "netguard.port_del", None, Some(id), None, None).await;
            Json(json!({"ok": true}))
        }
        Ok(_) => Json(json!({"ok": false, "error": "条目不存在或为内置模板（内置项只能停用）"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn toggle_port(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let r = sqlx::query("UPDATE netguard_ports SET enabled = NOT enabled, updated_at=CURRENT_TIMESTAMP WHERE id = ?")
        .bind(id).execute(&state.db).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ---- 域名拦截列表 ----

pub async fn list_domains(State(state): State<Arc<AppState>>) -> Json<Value> {
    let r = sqlx::query_as::<_, (i64, String, bool, Option<String>, Option<chrono::NaiveDateTime>)>(
        "SELECT id, domain, enabled, comment, created_at FROM netguard_domains ORDER BY id"
    ).fetch_all(&state.db).await;
    match r {
        Ok(rows) => Json(json!({"ok": true, "data": rows.iter().map(|r| json!({
            "id": r.0, "domain": r.1, "enabled": r.2, "comment": r.3, "created_at": r.4
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct DomainEntry {
    pub domain: String,
    pub comment: Option<String>,
}

pub async fn create_domain(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<DomainEntry>) -> Json<Value> {
    let domain = body.domain.trim().to_lowercase();
    if !valid_domain(&domain) {
        return Json(json!({"ok": false, "error": "域名格式无效"}));
    }
    let r = sqlx::query("INSERT INTO netguard_domains (domain, comment) VALUES (?, ?)")
        .bind(&domain).bind(&body.comment)
        .execute(&state.db).await;
    match r {
        Ok(_) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "netguard.domain_add", None, None, Some(&domain), None).await;
            Json(json!({"ok": true}))
        }
        Err(e) => Json(json!({"ok": false, "error": format!("添加失败（可能已存在）: {}", e)})),
    }
}

/// 批量导入域名（每行一个）
#[derive(Deserialize)]
pub struct DomainBatch {
    pub text: String,
}

pub async fn import_domains(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<DomainBatch>) -> Json<Value> {
    if body.text.len() > 256 * 1024 || body.text.lines().count() > 5000 {
        return Json(json!({"ok": false, "error": "批量导入过大（限 256KB / 5000 行）"}));
    }
    let mut added = 0;
    let mut skipped = 0;
    for line in body.text.lines() {
        let d = line.trim().to_lowercase();
        if d.is_empty() {
            continue;
        }
        if !valid_domain(&d) {
            skipped += 1;
            continue;
        }
        match sqlx::query("INSERT OR IGNORE INTO netguard_domains (domain) VALUES (?)").bind(&d).execute(&state.db).await {
            Ok(r) if r.rows_affected() > 0 => added += 1,
            Ok(_) => skipped += 1,
            Err(_) => skipped += 1,
        }
    }
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    crate::audit::log(&state.db, &actor, "netguard.domain_import", None, None,
        Some(&format!("added={} skipped={}", added, skipped)), None).await;
    Json(json!({"ok": true, "added": added, "skipped": skipped}))
}

pub async fn delete_domain(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>) -> Json<Value> {
    let r = sqlx::query("DELETE FROM netguard_domains WHERE id = ?").bind(id).execute(&state.db).await;
    match r {
        Ok(_) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "netguard.domain_del", None, Some(id), None, None).await;
            Json(json!({"ok": true}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn toggle_domain(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let r = sqlx::query("UPDATE netguard_domains SET enabled = NOT enabled WHERE id = ?")
        .bind(id).execute(&state.db).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ---- 生效范围与白名单 ----

pub async fn get_scope(State(state): State<Arc<AppState>>) -> Json<Value> {
    let rows = sqlx::query_as::<_, (i64, bool)>("SELECT host_id, enabled FROM netguard_scope")
        .fetch_all(&state.db).await;
    let wl = sqlx::query_as::<_, (i64, i64, i64, Option<String>)>("SELECT id, host_id, vmid, note FROM netguard_whitelist ORDER BY host_id, vmid")
        .fetch_all(&state.db).await;
    match (rows, wl) {
        (Ok(scope), Ok(wl)) => Json(json!({
            "ok": true,
            "scope": scope.iter().map(|r| json!({"host_id": r.0, "enabled": r.1})).collect::<Vec<_>>(),
            "whitelist": wl.iter().map(|r| json!({"id": r.0, "host_id": r.1, "vmid": r.2, "note": r.3})).collect::<Vec<_>>(),
        })),
        (Err(e), _) | (_, Err(e)) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct ScopeEntry {
    pub host_id: i64,
    pub enabled: bool,
}

/// 设置主机是否在管控范围内（安装或卸载组件由「下发」触发）
pub async fn set_scope(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<ScopeEntry>) -> Json<Value> {
    let r = sqlx::query(
        "INSERT INTO netguard_scope (host_id, enabled, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) \
         ON CONFLICT(host_id) DO UPDATE SET enabled=excluded.enabled, updated_at=CURRENT_TIMESTAMP"
    ).bind(body.host_id).bind(body.enabled).execute(&state.db).await;
    match r {
        Ok(_) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "netguard.scope", Some("host"), Some(body.host_id),
                Some(&format!("enabled={}", body.enabled)), None).await;
            Json(json!({"ok": true}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct WhitelistEntry {
    pub host_id: i64,
    pub vmid: i64,
    pub note: Option<String>,
}

pub async fn add_whitelist(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<WhitelistEntry>) -> Json<Value> {
    if !(1..=999_999_999).contains(&body.vmid) {
        return Json(json!({"ok": false, "error": "VMID 无效"}));
    }
    let r = sqlx::query("INSERT OR IGNORE INTO netguard_whitelist (host_id, vmid, note) VALUES (?, ?, ?)")
        .bind(body.host_id).bind(body.vmid).bind(&body.note).execute(&state.db).await;
    match r {
        Ok(_) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "netguard.whitelist_add", Some("host"), Some(body.host_id),
                Some(&format!("vmid={}", body.vmid)), None).await;
            Json(json!({"ok": true}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn del_whitelist(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>) -> Json<Value> {
    let r = sqlx::query("DELETE FROM netguard_whitelist WHERE id = ?").bind(id).execute(&state.db).await;
    match r {
        Ok(_) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "netguard.whitelist_del", None, Some(id), None, None).await;
            Json(json!({"ok": true}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ---- 下发与状态 ----

/// 把当前管控配置下发到所有生效主机（范围内的装/更新，范围外但已装的卸载）
pub async fn deploy(State(state): State<Arc<AppState>>, jar: CookieJar) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    let hosts = match crate::db::list_hosts(&state.db).await {
        Ok(h) => h,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    let scope: std::collections::HashMap<i64, bool> =
        sqlx::query_as::<_, (i64, bool)>("SELECT host_id, enabled FROM netguard_scope")
            .fetch_all(&state.db).await.unwrap_or_default()
            .into_iter().collect();
    let installed: std::collections::HashSet<i64> =
        sqlx::query_as::<_, (i64,)>("SELECT host_id FROM host_components WHERE component='netguard'")
            .fetch_all(&state.db).await.unwrap_or_default()
            .into_iter().map(|r| r.0).collect();

    let mut jobs_created: Vec<Value> = Vec::new();
    for host in &hosts {
        let in_scope = scope.get(&host.id).copied().unwrap_or(false);
        let has_component = installed.contains(&host.id);
        let spec = if in_scope && has_component {
            Some(crate::tasks::netguard_apply(&state, host.id).await)
        } else if in_scope {
            Some(crate::tasks::netguard_install(&state, host.id).await)
        } else if has_component {
            Some(Ok(crate::tasks::netguard_uninstall()))
        } else {
            None
        };
        if let Some(Ok(spec)) = spec {
            match crate::jobs::create_and_enqueue(&state, host.id, spec, &actor).await {
                Ok(id) => jobs_created.push(json!({"host": host.name, "job_id": id})),
                Err(e) => jobs_created.push(json!({"host": host.name, "error": e.to_string()})),
            }
        }
    }

    crate::audit::log(&state.db, &actor, "netguard.deploy", None, None,
        Some(&format!("{} 个任务", jobs_created.len())), None).await;
    Json(json!({"ok": true, "jobs": jobs_created}))
}

/// 各主机 netguard 状态（组件表 + 最近一次状态任务输出）
pub async fn status(State(state): State<Arc<AppState>>) -> Json<Value> {
    match crate::tasks::component_map(&state.db).await {
        Ok(map) => Json(json!({"ok": true, "components": map})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
