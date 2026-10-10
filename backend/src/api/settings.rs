//! 平台通用设置（白名单键）：platform_public_url / vmqos_version / vmqos_download_base
use axum::{extract::State, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

const ALLOWED_KEYS: [&str; 3] = ["platform_public_url", "vmqos_version", "vmqos_download_base"];

pub async fn get(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut out = serde_json::Map::new();
    for k in ALLOWED_KEYS {
        let v: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key=?")
            .bind(k).fetch_optional(&state.db).await.unwrap_or(None);
        out.insert(k.to_string(), json!(v.unwrap_or_default()));
    }
    Json(json!({"ok": true, "data": out}))
}

#[derive(Deserialize)]
pub struct PutBody {
    pub key: String,
    pub value: String,
}

pub async fn put(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<PutBody>) -> Json<Value> {
    if !ALLOWED_KEYS.contains(&body.key.as_str()) {
        return Json(json!({"ok": false, "error": "不支持的设置项"}));
    }
    let v = body.value.trim();
    if !v.is_empty() {
        // 值会插值进节点配置/命令：只允许安全字符
        if v.len() > 200 || v.chars().any(|c| !(c.is_ascii_alphanumeric() || "-._/:~".contains(c))) {
            return Json(json!({"ok": false, "error": "值含非法字符"}));
        }
        if body.key != "vmqos_version" && !v.starts_with("https://") && !v.starts_with("http://") {
            return Json(json!({"ok": false, "error": "URL 须以 http(s):// 开头"}));
        }
    }
    let r = sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(&body.key).bind(v).execute(&state.db).await;
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    crate::audit::log(&state.db, &actor, "settings.put", None, None, Some(&format!("{}={}", body.key, v)), None).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
