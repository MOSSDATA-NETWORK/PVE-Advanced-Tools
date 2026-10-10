//! P3 带宽 QoS 管理面 API：模板、策略、事件流、节点状态、token 管理、组件任务
use axum::{extract::{Path, Query, State}, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

async fn enqueue(state: &Arc<AppState>, jar: &CookieJar, host_id: i64, spec: crate::jobs::JobSpec, action: &str) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, jar).await;
    match crate::jobs::create_and_enqueue(state, host_id, spec, &actor).await {
        Ok(id) => {
            crate::audit::log(&state.db, &actor, action, Some("host"), Some(host_id), None, None).await;
            Json(json!({"ok": true, "job_id": id}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ==================== 档位模板（节点级） ====================

pub async fn list_templates(State(state): State<Arc<AppState>>) -> Json<Value> {
    let rows = sqlx::query_as::<_, (i64, String, String, i64, Option<String>)>(
        "SELECT id, name, config_json, builtin, created_at FROM qos_templates ORDER BY id"
    ).fetch_all(&state.db).await;
    match rows {
        Ok(r) => Json(json!({"ok": true, "data": r.iter().map(|(id, name, cfg, builtin, at)| json!({
            "id": id, "name": name, "config": serde_json::from_str::<Value>(cfg).unwrap_or(Value::Null),
            "builtin": *builtin == 1, "created_at": at
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct TemplateBody {
    pub name: String,
    pub config: Value,
}

pub async fn create_template(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<TemplateBody>) -> Json<Value> {
    if body.name.trim().is_empty() {
        return Json(json!({"ok": false, "error": "模板名不能为空"}));
    }
    if let Err(e) = crate::qos::validate_template(&body.config) {
        return Json(json!({"ok": false, "error": format!("模板校验失败：{}", e)}));
    }
    let r = sqlx::query("INSERT INTO qos_templates (name, config_json) VALUES (?, ?)")
        .bind(body.name.trim()).bind(body.config.to_string()).execute(&state.db).await;
    match r {
        Ok(res) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "qos.template.create", Some("qos_template"), Some(res.last_insert_rowid()), Some(&body.name), None).await;
            Json(json!({"ok": true, "id": res.last_insert_rowid()}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn delete_template(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>) -> Json<Value> {
    let builtin: Option<(i64,)> = sqlx::query_as("SELECT builtin FROM qos_templates WHERE id=?")
        .bind(id).fetch_optional(&state.db).await.unwrap_or(None);
    match builtin {
        None => return Json(json!({"ok": false, "error": "模板不存在"})),
        Some((1,)) => return Json(json!({"ok": false, "error": "内置模板不可删除"})),
        _ => {}
    }
    let in_use: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts WHERE qos_template_id=?")
        .bind(id).fetch_one(&state.db).await.unwrap_or(0);
    if in_use > 0 {
        return Json(json!({"ok": false, "error": format!("{} 台主机正在使用该模板", in_use)}));
    }
    let _ = sqlx::query("DELETE FROM qos_templates WHERE id=?").bind(id).execute(&state.db).await;
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    crate::audit::log(&state.db, &actor, "qos.template.delete", Some("qos_template"), Some(id), None, None).await;
    Json(json!({"ok": true}))
}

/// 设置节点生效模板（节点级，vmqos [stages] 全局单份）；template_id 为空 = 清除
#[derive(Deserialize)]
pub struct AssignTemplate {
    pub template_id: Option<i64>,
}

pub async fn assign_template(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>, Json(body): Json<AssignTemplate>) -> Json<Value> {
    if let Some(tid) = body.template_id {
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM qos_templates WHERE id=?")
            .bind(tid).fetch_one(&state.db).await.unwrap_or(0);
        if exists == 0 {
            return Json(json!({"ok": false, "error": "模板不存在"}));
        }
    }
    let r = sqlx::query("UPDATE hosts SET qos_template_id=? WHERE id=?")
        .bind(body.template_id).bind(host_id).execute(&state.db).await;
    if let Err(e) = r {
        return Json(json!({"ok": false, "error": e.to_string()}));
    }
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    crate::audit::log(&state.db, &actor, "qos.template.assign", Some("host"), Some(host_id),
        body.template_id.map(|t| t.to_string()).as_deref(), None).await;
    Json(json!({"ok": true}))
}

// ==================== VM 带宽策略 ====================

#[derive(Deserialize)]
pub struct PolicyQuery {
    pub host_id: Option<i64>,
}

pub async fn list_policies(State(state): State<Arc<AppState>>, Query(q): Query<PolicyQuery>) -> Json<Value> {
    let rows = if let Some(hid) = q.host_id {
        sqlx::query_as::<_, (i64, i64, Option<String>, String, String, i64, Option<i64>, i64)>(
            "SELECT id, host_id, vm_uuid, vmid, origin, initial_mbps, net2_mbps, enabled FROM qos_policies WHERE host_id=? ORDER BY vmid"
        ).bind(hid).fetch_all(&state.db).await
    } else {
        sqlx::query_as::<_, (i64, i64, Option<String>, String, String, i64, Option<i64>, i64)>(
            "SELECT id, host_id, vm_uuid, vmid, origin, initial_mbps, net2_mbps, enabled FROM qos_policies ORDER BY host_id, vmid"
        ).fetch_all(&state.db).await
    };
    match rows {
        Ok(r) => Json(json!({"ok": true, "data": r.iter().map(|(id, hid, uuid, vmid, origin, mbps, net2, enabled)| json!({
            "id": id, "host_id": hid, "vm_uuid": uuid, "vmid": vmid, "origin": origin,
            "initial_mbps": mbps, "net2_mbps": net2, "enabled": *enabled == 1
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct PolicyBody {
    pub host_id: i64,
    pub vmid: String,
    pub origin: String,
    pub initial_mbps: i64,
    pub net2_mbps: Option<i64>,
    pub enabled: Option<bool>,
}

fn validate_policy(body: &PolicyBody) -> Result<(), String> {
    if body.vmid.parse::<u32>().is_err() {
        return Err("vmid 须为数字".into());
    }
    if body.origin != "domestic" && body.origin != "international" {
        return Err("origin 须为 domestic 或 international".into());
    }
    let too_big = |v: i64| v > u32::MAX as i64;
    if body.initial_mbps < 0 || body.net2_mbps.map(|v| v < 0).unwrap_or(false) {
        return Err("速率不得为负（0 = 保留记录但跳过限速）".into());
    }
    if too_big(body.initial_mbps) || body.net2_mbps.map(too_big).unwrap_or(false) {
        return Err("速率超出 u32 上限".into());
    }
    if body.origin == "international" && body.net2_mbps.is_some() {
        return Err("net2 专线仅国内源支持".into());
    }
    Ok(())
}

pub async fn create_policy(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<PolicyBody>) -> Json<Value> {
    if let Err(e) = validate_policy(&body) {
        return Json(json!({"ok": false, "error": e}));
    }
    // 关联 VM 稳定标识（有 UUID 记录时绑定，迁移/克隆后可对账）
    let vm_uuid: Option<String> = sqlx::query_scalar(
        "SELECT uuid FROM vms WHERE host_id=? AND vmid=? AND uuid IS NOT NULL"
    ).bind(body.host_id).bind(&body.vmid).fetch_optional(&state.db).await.unwrap_or(None);
    let r = sqlx::query(
        "INSERT INTO qos_policies (host_id, vm_uuid, vmid, origin, initial_mbps, net2_mbps, enabled) VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(host_id, vmid, origin) DO UPDATE SET initial_mbps=excluded.initial_mbps, net2_mbps=excluded.net2_mbps, \
         vm_uuid=COALESCE(excluded.vm_uuid, qos_policies.vm_uuid), updated_at=CURRENT_TIMESTAMP"
    )
    .bind(body.host_id).bind(&vm_uuid).bind(&body.vmid).bind(&body.origin)
    .bind(body.initial_mbps).bind(body.net2_mbps).bind(body.enabled.unwrap_or(true))
    .execute(&state.db).await;
    match r {
        Ok(res) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "qos.policy.upsert", Some("host"), Some(body.host_id),
                Some(&format!("vmid={} {} {}Mbps", body.vmid, body.origin, body.initial_mbps)), None).await;
            Json(json!({"ok": true, "id": res.last_insert_rowid()}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn delete_policy(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>) -> Json<Value> {
    let _ = sqlx::query("DELETE FROM qos_policies WHERE id=?").bind(id).execute(&state.db).await;
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    crate::audit::log(&state.db, &actor, "qos.policy.delete", Some("qos_policy"), Some(id), None, None).await;
    Json(json!({"ok": true}))
}

pub async fn toggle_policy(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let _ = sqlx::query("UPDATE qos_policies SET enabled = 1 - enabled, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(id).execute(&state.db).await;
    Json(json!({"ok": true}))
}

// ==================== 事件流 ====================

#[derive(Deserialize)]
pub struct EventQuery {
    pub host_id: Option<i64>,
    pub vmid: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_events(State(state): State<Arc<AppState>>, Query(q): Query<EventQuery>) -> Json<Value> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0);
    let mut sql = String::from(
        "SELECT e.id, e.host_id, h.name, e.origin, e.vmid, e.stage, e.limit_mbps, e.reported_at \
         FROM qos_events e JOIN hosts h ON h.id=e.host_id WHERE 1=1"
    );
    if q.host_id.is_some() { sql.push_str(" AND e.host_id=?"); }
    if q.vmid.is_some() { sql.push_str(" AND e.vmid=?"); }
    sql.push_str(" ORDER BY e.id DESC LIMIT ? OFFSET ?");
    let mut query = sqlx::query_as::<_, (i64, i64, String, String, String, i64, Option<f64>, Option<String>)>(&sql);
    if let Some(h) = q.host_id { query = query.bind(h); }
    if let Some(v) = &q.vmid { query = query.bind(v); }
    match query.bind(limit).bind(offset).fetch_all(&state.db).await {
        Ok(r) => Json(json!({"ok": true, "data": r.iter().map(|(id, hid, hname, origin, vmid, stage, limit, at)| json!({
            "id": id, "host_id": hid, "host": hname, "origin": origin, "vmid": vmid,
            "stage": stage, "limit_mbps": limit, "reported_at": at
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ==================== 节点状态 ====================

pub async fn list_nodes(State(state): State<Arc<AppState>>) -> Json<Value> {
    let rows = sqlx::query_as::<_, (i64, String, String, Option<String>, Option<String>, Option<String>, Option<i64>, Option<String>, Option<String>)>(
        "SELECT h.id, h.name, h.host, h.host_key_status, s.last_snapshot_at, s.last_report_at, h.qos_template_id, t.name, s.last_error \
         FROM hosts h LEFT JOIN qos_node_status s ON s.host_id=h.id LEFT JOIN qos_templates t ON t.id=h.qos_template_id \
         WHERE EXISTS (SELECT 1 FROM host_components c WHERE c.host_id=h.id AND c.component='vmqos') \
            OR EXISTS (SELECT 1 FROM qos_tokens tk WHERE tk.host_id=h.id AND tk.status != 'revoked') \
         ORDER BY h.id"
    ).fetch_all(&state.db).await;
    match rows {
        Ok(r) => Json(json!({"ok": true, "data": r.iter().map(|(id, name, addr, ks, snap, report, tid, tname, err)| {
            let last_snap = snap.as_deref().and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok());
            json!({
                "host_id": id, "name": name, "host": addr, "host_key_status": ks,
                "status": crate::qos::infer_node_status(last_snap, err),
                "last_snapshot_at": snap, "last_report_at": report,
                "template_id": tid, "template_name": tname, "last_error": err
            })
        }).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ==================== 接入 token ====================

/// 签发/轮换 token（重叠轮换：旧 token 转 retiring，配置下发成功后撤销）。明文仅此一次返回。
#[derive(Deserialize)]
pub struct TokenBody {
    pub purpose: String,
}

pub async fn issue_token(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>, Json(body): Json<TokenBody>) -> Json<Value> {
    if !["snapshot", "report", "intl"].contains(&body.purpose.as_str()) {
        return Json(json!({"ok": false, "error": "purpose 须为 snapshot/report/intl"}));
    }
    match crate::qos::issue_token(&state.db, &state.master_key, host_id, &body.purpose).await {
        Ok(token) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "qos.token.issue", Some("host"), Some(host_id), Some(&body.purpose), None).await;
            Json(json!({"ok": true, "token": token, "note": "明文仅此一次显示；旧 token 在下次配置下发成功后撤销"}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// token 列表（仅状态与时间，不回显明文/密文/哈希）
pub async fn list_tokens(State(state): State<Arc<AppState>>, Path(host_id): Path<i64>) -> Json<Value> {
    let rows = sqlx::query_as::<_, (i64, String, String, Option<String>, Option<String>)>(
        "SELECT id, purpose, status, created_at, last_used_at FROM qos_tokens WHERE host_id=? AND status != 'revoked' ORDER BY purpose, id"
    ).bind(host_id).fetch_all(&state.db).await;
    match rows {
        Ok(r) => Json(json!({"ok": true, "data": r.iter().map(|(id, p, s, c, u)| json!({
            "id": id, "purpose": p, "status": s, "created_at": c, "last_used_at": u
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ==================== 集群 ====================

pub async fn list_clusters(State(state): State<Arc<AppState>>) -> Json<Value> {
    let rows = sqlx::query_as::<_, (i64, String)>("SELECT id, name FROM clusters ORDER BY id")
        .fetch_all(&state.db).await;
    match rows {
        Ok(r) => Json(json!({"ok": true, "data": r.iter().map(|(id, n)| json!({"id": id, "name": n})).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct ClusterBody {
    pub name: String,
}

pub async fn create_cluster(State(state): State<Arc<AppState>>, Json(body): Json<ClusterBody>) -> Json<Value> {
    if body.name.trim().is_empty() {
        return Json(json!({"ok": false, "error": "集群名不能为空"}));
    }
    match sqlx::query("INSERT INTO clusters (name) VALUES (?)").bind(body.name.trim()).execute(&state.db).await {
        Ok(r) => Json(json!({"ok": true, "id": r.last_insert_rowid()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ==================== 组件任务 ====================

pub async fn install(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    match crate::tasks::qos_install(&state, host_id).await {
        Ok(spec) => enqueue(&state, &jar, host_id, spec, "qos.install").await,
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn config_apply(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    match crate::tasks::qos_config_apply(&state, host_id).await {
        Ok(spec) => enqueue(&state, &jar, host_id, spec, "qos.config_apply").await,
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn uninstall(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    enqueue(&state, &jar, host_id, crate::tasks::qos_uninstall(), "qos.uninstall").await
}

pub async fn status(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    enqueue(&state, &jar, host_id, crate::tasks::qos_status(), "qos.status").await
}
