//! 平台通用设置（白名单键）：platform_public_url / vmqos_version / vmqos_download_base
use axum::{extract::State, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

const ALLOWED_KEYS: [&str; 4] = ["platform_public_url", "vmqos_version", "vmqos_download_base", "github_mirror_token"];
/// 敏感键：加密存储、读取只回显是否已配置
const SECRET_KEYS: [&str; 1] = ["github_mirror_token"];

pub async fn get(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut out = serde_json::Map::new();
    for k in ALLOWED_KEYS {
        let v: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key=?")
            .bind(k).fetch_optional(&state.db).await.unwrap_or(None);
        let masked = if SECRET_KEYS.contains(&k) {
            json!(if v.as_deref().map(|x| !x.is_empty()).unwrap_or(false) { "***" } else { "" })
        } else {
            json!(v.unwrap_or_default())
        };
        out.insert(k.to_string(), masked);
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
    // 掩码值视为未修改
    if SECRET_KEYS.contains(&body.key.as_str()) && v == "***" {
        return Json(json!({"ok": true, "note": "未修改"}));
    }
    if !v.is_empty() {
        // 值会插值进节点配置/命令：只允许安全字符
        if v.len() > 200 || v.chars().any(|c| !(c.is_ascii_alphanumeric() || "-._/:~".contains(c))) {
            return Json(json!({"ok": false, "error": "值含非法字符"}));
        }
        if !["vmqos_version", "github_mirror_token"].contains(&body.key.as_str())
            && !v.starts_with("https://") && !v.starts_with("http://") {
            return Json(json!({"ok": false, "error": "URL 须以 http(s):// 开头"}));
        }
    }
    // 敏感键加密存储
    let stored;
    let v = if SECRET_KEYS.contains(&body.key.as_str()) && !v.is_empty() {
        stored = crate::crypto::encrypt(v, &state.master_key);
        &stored
    } else {
        v
    };
    let r = sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(&body.key).bind(v).execute(&state.db).await;
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    crate::audit::log(&state.db, &actor, "settings.put", None, None, Some(&format!("{}={}", body.key, v)), None).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
