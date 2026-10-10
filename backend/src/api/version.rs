use axum::{extract::State, Json};
use axum_extra::extract::CookieJar;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

/// 获取当前版本
pub async fn current() -> Json<Value> {
    Json(json!({
        "ok": true,
        "version": crate::version::VERSION
    }))
}

/// 检查更新
pub async fn check() -> Json<Value> {
    match crate::version::check_update().await {
        Ok(info) => Json(json!({"ok": true, "data": info})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 获取更新日志
pub async fn changelog() -> Json<Value> {
    match crate::version::get_changelog().await {
        Ok(entries) => Json(json!({"ok": true, "data": entries})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 执行更新（危险操作：先写审计再执行）
pub async fn update(State(state): State<Arc<AppState>>, jar: CookieJar) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    crate::audit::log(&state.db, &actor, "system.update", Some("system"), None,
        Some(&format!("from {}", crate::version::VERSION)), None).await;
    match crate::version::perform_update(&state.db).await {
        Ok(msg) => Json(json!({"ok": true, "message": msg})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
