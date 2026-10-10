/// Passkey API 端点
use axum::{extract::State, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

#[derive(Deserialize)]
pub struct PasskeyLoginStartRequest {
    pub username: Option<String>,
}

#[derive(Deserialize)]
pub struct PasskeyLoginFinishRequest {
    pub username: Option<String>,
    pub credential: serde_json::Value,
}

/// Passkey 注册：生成挑战
pub async fn register_start(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Json<Value> {
    let user_id = match get_user_id(&state, &jar).await {
        Some(id) => id,
        None => return Json(json!({"ok": false, "error": "未登录"})),
    };

    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or_default();

    let challenge = crate::passkey::generate_challenge();

    // 存储 challenge（带时间戳，5分钟过期）
    let challenge_data = format!("{}:{}", chrono::Utc::now().timestamp(), challenge);
    sqlx::query("INSERT OR REPLACE INTO settings (key, value) VALUES ('passkey_reg_challenge', ?)")
        .bind(&challenge_data)
        .execute(&state.db)
        .await
        .ok();

    // 获取已有的凭据 ID（避免重复注册）
    let existing_creds = crate::passkey::get_user_credential_ids(&state.db, &username).await;

    Json(json!({
        "ok": true,
        "challenge": challenge,
        "rp": {
            "id": crate::passkey::get_rp_id(),
            "name": crate::passkey::RP_NAME,
        },
        "user": {
            "id": user_id.to_string(),
            "name": username,
            "displayName": username,
        },
        "excludeCredentials": existing_creds,
    }))
}

/// Passkey 注册：验证并存储
pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(resp): Json<serde_json::Value>,
) -> Json<Value> {
    let user_id = match get_user_id(&state, &jar).await {
        Some(id) => id,
        None => return Json(json!({"ok": false, "error": "未登录"})),
    };

    // 获取存储的 challenge（检查过期）
    let challenge_raw: String = sqlx::query_scalar(
        "SELECT value FROM settings WHERE key = 'passkey_reg_challenge'"
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or_default();

    let challenge = match validate_challenge_ttl(&challenge_raw) {
        Some(c) => c,
        None => return Json(json!({"ok": false, "error": "挑战已过期，请重新注册"})),
    };

    // 解析响应
    let reg_resp: crate::passkey::RegistrationResponse = match serde_json::from_value(resp) {
        Ok(r) => r,
        Err(e) => return Json(json!({"ok": false, "error": format!("响应格式错误: {}", e)})),
    };

    match crate::passkey::verify_and_store_credential(&state.db, user_id, &reg_resp, &challenge).await {
        Ok(_) => {
            // 清除 challenge
            sqlx::query("DELETE FROM settings WHERE key = 'passkey_reg_challenge'")
                .execute(&state.db)
                .await
                .ok();
            Json(json!({"ok": true, "message": "Passkey 注册成功"}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// Passkey 登录：生成挑战
/// 有用户名 → 指定 allowCredentials
/// 无用户名 → discoverable credentials（浏览器自己选）
pub async fn login_start(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PasskeyLoginStartRequest>,
) -> Json<Value> {
    let challenge = crate::passkey::generate_challenge();

    // 存储 challenge（带时间戳）
    let challenge_data = format!("{}:{}", chrono::Utc::now().timestamp(), challenge);
    sqlx::query("INSERT OR REPLACE INTO settings (key, value) VALUES ('passkey_auth_challenge', ?)")
        .bind(&challenge_data)
        .execute(&state.db)
        .await
        .ok();

    match body.username {
        Some(username) => {
            // 有用户名 → 指定凭据
            let allow_creds = crate::passkey::get_user_credential_ids(&state.db, &username).await;
            if allow_creds.is_empty() {
                return Json(json!({"ok": false, "error": "该用户未注册 Passkey"}));
            }
            Json(json!({
                "ok": true,
                "challenge": challenge,
                "rpId": crate::passkey::get_rp_id(),
                "allowCredentials": allow_creds,
            }))
        }
        None => {
            // 无用户名 → discoverable credentials
            Json(json!({
                "ok": true,
                "challenge": challenge,
                "rpId": crate::passkey::get_rp_id(),
                "allowCredentials": [],
            }))
        }
    }
}

/// Passkey 登录：验证签名
pub async fn login_finish(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<PasskeyLoginFinishRequest>,
) -> (CookieJar, Json<Value>) {
    let jar = CookieJar::new();

    // 提取客户端 IP
    let client_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(|s| s.to_string()));

    // 获取存储的 challenge（检查过期）
    let challenge_raw: String = sqlx::query_scalar(
        "SELECT value FROM settings WHERE key = 'passkey_auth_challenge'"
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or_default();

    let challenge = match validate_challenge_ttl(&challenge_raw) {
        Some(c) => c,
        None => return (jar, Json(json!({"ok": false, "error": "挑战已过期，请重新登录"}))),
    };

    // 解析响应
    let auth_resp: crate::passkey::AuthenticationResponse = match serde_json::from_value(body.credential) {
        Ok(r) => r,
        Err(e) => return (jar, Json(json!({"ok": false, "error": format!("响应格式错误: {}", e)}))),
    };

    match crate::passkey::verify_authentication(&state.db, &auth_resp, &challenge).await {
        Ok(Some(user_id)) => {
            // 清除 challenge
            sqlx::query("DELETE FROM settings WHERE key = 'passkey_auth_challenge'")
                .execute(&state.db)
                .await
                .ok();

            // 创建 session
            match crate::auth::create_session(&state.db, user_id, true, client_ip.as_deref()).await {
                Ok(token) => {
                    let cookie = crate::auth::build_session_cookie(&token, state.tls_enabled);
                    let jar = jar.add(cookie);
                    (jar, Json(json!({"ok": true, "message": "Passkey 登录成功"})))
                }
                Err(e) => (jar, Json(json!({"ok": false, "error": e.to_string()}))),
            }
        }
        Ok(None) => (jar, Json(json!({"ok": false, "error": "未找到匹配的凭据"}))),
        Err(e) => (jar, Json(json!({"ok": false, "error": e.to_string()}))),
    }
}

/// 删除 Passkey 凭据
pub async fn delete(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Json<Value> {
    let user_id = match get_user_id(&state, &jar).await {
        Some(id) => id,
        None => return Json(json!({"ok": false, "error": "未登录"})),
    };

    match crate::passkey::delete_credentials(&state.db, user_id).await {
        Ok(_) => Json(json!({"ok": true, "message": "Passkey 已删除"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 检查用户是否有 Passkey（可选用户名，不传则检查是否有任何用户注册了 Passkey）
pub async fn has_passkey(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PasskeyLoginStartRequest>,
) -> Json<Value> {
    match body.username {
        Some(username) => {
            let cred_ids = crate::passkey::get_user_credential_ids(&state.db, &username).await;
            Json(json!({
                "ok": true,
                "has_passkey": !cred_ids.is_empty(),
                "credential_count": cred_ids.len(),
            }))
        }
        None => {
            // 检查是否有任何用户注册了 Passkey
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users WHERE passkey_credential IS NOT NULL"
            )
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);
            Json(json!({
                "ok": true,
                "has_passkey": count > 0,
                "credential_count": count,
            }))
        }
    }
}

async fn get_user_id(state: &AppState, jar: &CookieJar) -> Option<i64> {
    let token = jar.get("session")?.value();
    sqlx::query_scalar("SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')")
        .bind(token)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None)
}

/// 验证 challenge TTL（格式：timestamp:challenge，5分钟过期）
fn validate_challenge_ttl(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let timestamp: i64 = parts[0].parse().ok()?;
    let challenge = parts[1].to_string();
    let now = chrono::Utc::now().timestamp();
    if now - timestamp > 300 {
        return None; // 过期
    }
    Some(challenge)
}
