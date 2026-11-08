use axum::{extract::{State, ConnectInfo}, http::HeaderMap, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

/// 从请求头提取客户端 IP：仅当直连对端是回环地址（本机反代）时才信任转发头，
/// 否则用对端地址——外部直连客户端伪造 XFF 不能绕过登录限流
fn extract_ip(headers: &HeaderMap, peer: &std::net::SocketAddr) -> Option<String> {
    if !peer.ip().is_loopback() {
        return Some(peer.ip().to_string());
    }
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            for part in val.split(',').rev() {
                let ip = part.trim();
                if !ip.is_empty() && ip != "127.0.0.1" && ip != "::1" {
                    return Some(ip.to_string());
                }
            }
        }
    }
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(val) = xri.to_str() {
            let ip = val.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }
    Some(peer.ip().to_string())
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct PasswordRequest {
    pub password: String,
}

/// 检查是否已初始化
pub async fn check_auth(State(state): State<Arc<AppState>>) -> Json<Value> {
    let initialized = crate::auth::is_initialized(&state.db).await;
    Json(json!({"ok": true, "initialized": initialized}))
}

/// 首次运行 Setup（仅允许本机回环地址，防外部抢建管理员）
pub async fn setup(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<SetupRequest>,
) -> (CookieJar, Json<Value>) {
    let jar = CookieJar::new();

    if crate::auth::is_initialized(&state.db).await {
        return (jar, Json(json!({"ok": false, "error": "管理员已存在，请直接登录"})));
    }

    // 初始化页面对外开放（用户决策 2026-10-10：接受部署后到初始化前的抢建窗口，
    // 被抢先可重装）；is_initialized 上面的检查保证只有一次机会。
    // 保留限流（复用登录限流器）防爆破。
    let client_ip = extract_ip(&headers, &addr);

    match crate::auth::setup_admin(&state.db, &body.username, &body.password).await {
        Ok(user_id) => {
            match crate::auth::create_session(&state.db, user_id, false, client_ip.as_deref()).await {
                Ok(token) => {
                    let cookie = crate::auth::build_session_cookie(&token, state.tls_enabled);
                    let jar = jar.add(cookie);
                    (jar, Json(json!({
                        "ok": true,
                        "needs_enrollment": true,
                        "message": "账户已创建，请绑定二次验证"
                    })))
                }
                Err(e) => (jar, Json(json!({"ok": false, "error": e.to_string()}))),
            }
        }
        Err(e) => (jar, Json(json!({"ok": false, "error": e.to_string()}))),
    }
}

/// 登录（带速率限制）
pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> (CookieJar, Json<Value>) {
    let jar = CookieJar::new();
    let client_ip = extract_ip(&headers, &peer);

    // 速率限制检查（按用户名+IP）
    let rate_key = format!("login:{}:{}", body.username, client_ip.as_deref().unwrap_or("unknown"));
    if !state.login_limiter.check(&rate_key).await {
        let remaining = state.login_limiter.remaining_secs(&rate_key).await;
        return (jar, Json(json!({
            "ok": false,
            "error": format!("登录尝试次数过多，请 {} 秒后重试", remaining)
        })));
    }

    match crate::auth::login(&state.db, &body.username, &body.password, client_ip.as_deref()).await {
        Ok(outcome) => {
            // 登录成功，清除限制
            state.login_limiter.clear(&rate_key).await;
            let token = match &outcome {
                crate::auth::LoginOutcome::NeedsTotp(t) | crate::auth::LoginOutcome::NeedsEnrollment(t) => t,
            };
            let cookie = crate::auth::build_session_cookie(token, state.tls_enabled);
            let jar = jar.add(cookie);
            let body = match outcome {
                crate::auth::LoginOutcome::NeedsTotp(_) => json!({
                    "ok": true,
                    "needs_mfa": true,
                    "needs_enrollment": false,
                    "message": "需要二次验证"
                }),
                crate::auth::LoginOutcome::NeedsEnrollment(_) => json!({
                    "ok": true,
                    "needs_mfa": false,
                    "needs_enrollment": true,
                    "message": "请先绑定二次验证"
                }),
            };
            (jar, Json(body))
        }
        Err(e) => {
            // 登录失败，记录（含仅 Passkey 账户的密码尝试）
            state.login_limiter.record_failure(&rate_key).await;
            (jar, Json(json!({"ok": false, "error": e.to_string()})))
        }
    }
}

/// TOTP 验证（带限流）
pub async fn verify_totp(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(body): Json<TotpVerifyRequest>,
) -> Json<Value> {
    let token = match jar.get("session") {
        Some(c) => c.value().to_string(),
        None => return Json(json!({"ok": false, "error": "未登录"})),
    };

    match crate::auth::verify_totp(&state.db, &token, &body.code, &state.login_limiter).await {
        Ok(true) => Json(json!({"ok": true, "message": "验证成功"})),
        Ok(false) => Json(json!({"ok": false, "error": "验证码错误"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 登出
pub async fn logout(jar: CookieJar, State(state): State<Arc<AppState>>) -> (CookieJar, Json<Value>) {
    if let Some(cookie) = jar.get("session") {
        let _ = sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(cookie.value())
            .execute(&state.db)
            .await;
    }
    let mut remove_cookie = axum_extra::extract::cookie::Cookie::from("session");
    remove_cookie.set_path("/");
    let jar = jar.remove(remove_cookie);
    (jar, Json(json!({"ok": true, "message": "已退出"})))
}

/// 修改密码
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(body): Json<ChangePasswordRequest>,
) -> Json<Value> {
    let token = match jar.get("session") {
        Some(c) => c.value().to_string(),
        None => return Json(json!({"ok": false, "error": "未登录"})),
    };

    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')"
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let user_id = match user_id {
        Some(id) => id,
        None => return Json(json!({"ok": false, "error": "会话无效"})),
    };

    match crate::auth::change_password(&state.db, user_id, &body.old_password, &body.new_password).await {
        Ok(_) => Json(json!({"ok": true, "message": "密码已修改，请重新登录"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

fn session_token(jar: &CookieJar) -> Option<String> {
    jar.get("session").map(|c| c.value().to_string())
}

/// 生成待确认的 TOTP 密钥。不改已生效的 totp_secret。
pub async fn totp_setup(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(body): Json<PasswordRequest>,
) -> Json<Value> {
    let Some(token) = session_token(&jar) else {
        return Json(json!({"ok": false, "error": "未登录"}));
    };
    let ctx = match crate::auth::enrollment_ctx(&state.db, Some(&token)).await {
        Ok(c) => c,
        Err(e) => return Json(json!({"ok": false, "error": e})),
    };

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT password_hash, username FROM users WHERE id = ?"
    )
    .bind(ctx.user_id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);
    let Some((hash, username)) = row else {
        return Json(json!({"ok": false, "error": "用户不存在"}));
    };
    if !crate::crypto::verify_password(&body.password, &hash) {
        return Json(json!({"ok": false, "error": "密码错误"}));
    }

    let secret = crate::totp::generate_secret();
    if let Err(e) = sqlx::query("UPDATE users SET totp_pending_secret = ? WHERE id = ?")
        .bind(&secret)
        .bind(ctx.user_id)
        .execute(&state.db)
        .await
    {
        return Json(json!({"ok": false, "error": e.to_string()}));
    }
    let uri = crate::totp::get_otpauth_uri(&username, &secret);
    Json(json!({
        "ok": true,
        "totp_secret": secret,
        "totp_uri": uri,
        "message": "请扫描二维码并输入验证码完成绑定"
    }))
}

/// 确认待绑定的 TOTP，成功后把当前会话标为已验证。
pub async fn totp_confirm(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(body): Json<TotpVerifyRequest>,
) -> Json<Value> {
    let Some(token) = session_token(&jar) else {
        return Json(json!({"ok": false, "error": "未登录"}));
    };
    let ctx = match crate::auth::enrollment_ctx(&state.db, Some(&token)).await {
        Ok(c) => c,
        Err(e) => return Json(json!({"ok": false, "error": e})),
    };

    let rate_key = format!("totp-confirm:{token}");
    if !state.login_limiter.check(&rate_key).await {
        let n = state.login_limiter.remaining_secs(&rate_key).await;
        return Json(json!({"ok": false, "error": format!("验证尝试次数过多，请 {n} 秒后重试")}));
    }

    let pending: Option<String> = sqlx::query_scalar(
        "SELECT totp_pending_secret FROM users WHERE id = ?"
    )
    .bind(ctx.user_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .flatten();
    let Some(pending) = pending.filter(|s| !s.trim().is_empty()) else {
        return Json(json!({"ok": false, "error": "请先获取新的 TOTP 密钥"}));
    };
    if !crate::totp::verify_code(&pending, &body.code) {
        state.login_limiter.record_failure(&rate_key).await;
        return Json(json!({"ok": false, "error": "验证码错误"}));
    }

    match crate::auth::promote_pending_totp(
        &state.db,
        ctx.user_id,
        ctx.session_verified,
        &pending,
        ctx.passkey_json.as_deref(),
    ).await {
        Ok(true) => {
            state.login_limiter.clear(&rate_key).await;
            if let Err(e) = crate::auth::mark_session_verified(&state.db, &token).await {
                return Json(json!({"ok": false, "error": e.to_string()}));
            }
            Json(json!({"ok": true, "message": "TOTP 已绑定"}))
        }
        Ok(false) => Json(json!({"ok": false, "error": "账户状态已变化，请刷新后重试"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 禁用 TOTP
pub async fn disable_totp(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(body): Json<PasswordRequest>,
) -> Json<Value> {
    let token = match jar.get("session") {
        Some(c) => c.value().to_string(),
        None => return Json(json!({"ok": false, "error": "未登录"})),
    };

    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')"
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let user_id = match user_id {
        Some(id) => id,
        None => return Json(json!({"ok": false, "error": "会话无效"})),
    };

    let password_hash: Option<String> = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    match password_hash {
        Some(hash) => {
            if !crate::crypto::verify_password(&body.password, &hash) {
                return Json(json!({"ok": false, "error": "密码错误"}));
            }
        }
        None => return Json(json!({"ok": false, "error": "用户不存在"})),
    }

    let passkey_json: Option<String> = sqlx::query_scalar(
        "SELECT passkey_credential FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .flatten();
    if !passkey_json.as_deref().is_some_and(crate::passkey::has_usable_credential) {
        return Json(json!({"ok": false, "error": "TOTP 是当前唯一的登录验证方式，请先注册 Passkey 再禁用"}));
    }

    let updated = sqlx::query(
        "UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL WHERE id = ? AND passkey_credential IS ?"
    )
    .bind(user_id)
    .bind(passkey_json.as_deref())
    .execute(&state.db)
    .await;
    match updated {
        Ok(r) if r.rows_affected() == 1 => Json(json!({"ok": true, "message": "TOTP 已禁用"})),
        Ok(_) => Json(json!({"ok": false, "error": "账户状态已变化，请刷新后重试"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
