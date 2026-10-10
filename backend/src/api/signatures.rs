//! 切鸡检测特征库 API（M2）：CRUD + 下发到节点
use axum::{extract::{Path, State}, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

pub async fn list(State(state): State<Arc<AppState>>) -> Json<Value> {
    let rows = sqlx::query_as::<_, (i64, String, String, String, i64, i64, Option<String>)>(
        "SELECT id, name, sig_type, value, enabled, builtin, created_at FROM detect_signatures ORDER BY id"
    ).fetch_all(&state.db).await;
    match rows {
        Ok(r) => Json(json!({"ok": true, "data": r.iter().map(|(id, name, t, v, e, b, at)| json!({
            "id": id, "name": name, "sig_type": t, "value": v,
            "enabled": *e == 1, "builtin": *b == 1, "created_at": at
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct SigBody {
    pub name: String,
    pub sig_type: String,
    pub value: String,
}

fn validate_sig(body: &SigBody) -> Result<(), String> {
    if !["path", "service", "history"].contains(&body.sig_type.as_str()) {
        return Err("类型须为 path / service / history".into());
    }
    let ok = |x: &str| !x.is_empty() && x.len() <= 200
        && x.chars().all(|c| c.is_ascii_alphanumeric() || ".-_/~:".contains(c));
    if !ok(&body.value) || !ok(&body.name) {
        return Err("名称与值只允许字母数字与 . - _ / ~ : 字符（≤200 字）".into());
    }
    if body.sig_type == "path" && !body.value.starts_with('/') {
        return Err("path 类型须为绝对路径".into());
    }
    Ok(())
}

pub async fn create(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<SigBody>) -> Json<Value> {
    if let Err(e) = validate_sig(&body) {
        return Json(json!({"ok": false, "error": e}));
    }
    let r = sqlx::query("INSERT INTO detect_signatures (name, sig_type, value) VALUES (?, ?, ?)")
        .bind(body.name.trim()).bind(&body.sig_type).bind(body.value.trim())
        .execute(&state.db).await;
    match r {
        Ok(res) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "signature.create", Some("detect_signatures"), Some(res.last_insert_rowid()), Some(&body.name), None).await;
            Json(json!({"ok": true, "id": res.last_insert_rowid(), "note": "需在主机上「下发特征库」后生效"}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn toggle(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let _ = sqlx::query("UPDATE detect_signatures SET enabled = 1 - enabled WHERE id=?")
        .bind(id).execute(&state.db).await;
    Json(json!({"ok": true}))
}

pub async fn delete(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>) -> Json<Value> {
    let builtin: Option<(i64,)> = sqlx::query_as("SELECT builtin FROM detect_signatures WHERE id=?")
        .bind(id).fetch_optional(&state.db).await.unwrap_or(None);
    if let Some((1,)) = builtin {
        return Json(json!({"ok": false, "error": "内置特征不可删除（可停用）"}));
    }
    let _ = sqlx::query("DELETE FROM detect_signatures WHERE id=?").bind(id).execute(&state.db).await;
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    crate::audit::log(&state.db, &actor, "signature.delete", Some("detect_signatures"), Some(id), None, None).await;
    Json(json!({"ok": true}))
}

/// 下发特征库到指定主机
pub async fn push(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    match crate::tasks::detect_push_signatures(&state, host_id).await {
        Ok(spec) => match crate::jobs::create_and_enqueue(&state, host_id, spec, &actor).await {
            Ok(id) => {
                crate::audit::log(&state.db, &actor, "signature.push", Some("host"), Some(host_id), None, None).await;
                Json(json!({"ok": true, "job_id": id}))
            }
            Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
        },
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
