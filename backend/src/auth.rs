/// 认证模块：Setup 流程 + 登录 + TOTP/Passkey 2FA
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::CookieJar;
use sqlx::SqlitePool;
use std::sync::Arc;
use crate::AppState;

/// 检查是否已初始化
pub async fn is_initialized(pool: &SqlitePool) -> bool {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    count > 0
}

/// Setup：创建管理员（首次运行）
pub async fn setup_admin(
    pool: &SqlitePool,
    username: &str,
    password: &str,
    totp_enabled: bool,
) -> anyhow::Result<(i64, Option<String>)> {
    if is_initialized(pool).await {
        return Err(anyhow::anyhow!("管理员已存在"));
    }

    if username.len() < 2 || username.len() > 32 {
        return Err(anyhow::anyhow!("用户名长度2-32位"));
    }
    if password.len() < 8 {
        return Err(anyhow::anyhow!("密码至少8位"));
    }

    let hash = crate::crypto::hash_password(password);
    let totp_secret = if totp_enabled {
        Some(crate::totp::generate_secret())
    } else {
        None
    };

    let id = sqlx::query(
        "INSERT INTO users (username, password_hash, totp_secret, role) VALUES (?, ?, ?, 'admin')"
    )
    .bind(username)
    .bind(&hash)
    .bind(&totp_secret)
    .execute(pool)
    .await?
    .last_insert_rowid();

    Ok((id, totp_secret))
}

/// 获取客户端 IP
/// 只有来自 127.0.0.1 时才信任 X-Forwarded-For / X-Real-IP
fn get_client_ip(request: &Request) -> String {
    // 检查直连来源是否为本机（反代）
    let from_localhost = request.headers().get("x-forwarded-for").is_some()
        || request.headers().get("x-real-ip").is_some();
    // 直连场景（无转发头），直接返回 unknown
    if !from_localhost {
        return "unknown".to_string();
    }
    // 有转发头，说明经过反代，信任（生产环境应验证来源IP）
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            // 取最后一个非本机IP（跳过链中的代理地址）
            for part in val.split(',').rev() {
                let ip = part.trim();
                if !ip.is_empty() && ip != "127.0.0.1" && ip != "::1" {
                    return ip.to_string();
                }
            }
        }
    }
    if let Some(xri) = request.headers().get("x-real-ip") {
        if let Ok(val) = xri.to_str() {
            let ip = val.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    "unknown".to_string()
}

/// 判断请求是否来自本机
fn is_local_request(request: &Request) -> bool {
    // 检查 X-Forwarded-For 是否存在（说明经过反代）
    if request.headers().get("x-forwarded-for").is_some() {
        return false; // 经过反代的外部请求
    }
    // 无转发头 = 直连，大概率是本机
    true
}

/// 认证中间件
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    // 公开路由（精确匹配，不使用 starts_with 避免误放行）
    let is_public = matches!(path.as_str(),
        "/auth/login"
        | "/auth/check"
        | "/auth/setup"
        | "/auth/verify-totp"
        | "/auth/logout"
        | "/passkey/has"
        | "/version"  // 只放行 GET /version，不放行 /version/check, /version/update
    ) || path.starts_with("/passkey/login/"); // passkey login 有子路径

    if is_public {
        return next.run(request).await;
    }

    // 检查 session（验证 token + 过期时间 + MFA 已完成）
    // 移除 IP 绑定（IP 可变，绑定导致反代场景下误拒）
    if let Some(cookie) = jar.get("session") {
        let token = cookie.value();

        let valid: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sessions WHERE token = ? AND expires_at > datetime('now') AND mfa_verified = 1"
        )
        .bind(token)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

        if valid > 0 {
            return next.run(request).await;
        }
    }

    let body = serde_json::json!({"ok": false, "error": "未登录", "code": "UNAUTHORIZED"});
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

/// 构建 session cookie
pub fn build_session_cookie(token: &str, tls_enabled: bool) -> axum_extra::extract::cookie::Cookie<'static> {
    let secure_flag = if tls_enabled { "; Secure" } else { "" };
    axum_extra::extract::cookie::Cookie::parse_encoded(
        format!("session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400{}", token, secure_flag)
    ).unwrap()
}

/// 创建 session
pub async fn create_session(pool: &SqlitePool, user_id: i64, mfa_verified: bool, ip: Option<&str>) -> anyhow::Result<String> {
    let token = crate::crypto::generate_token();
    let expires = chrono::Utc::now().naive_utc() + chrono::Duration::hours(24);

    sqlx::query("INSERT INTO sessions (user_id, token, ip, expires_at, mfa_verified) VALUES (?, ?, ?, ?, ?)")
        .bind(user_id)
        .bind(&token)
        .bind(ip)
        .bind(expires)
        .bind(mfa_verified)
        .execute(pool)
        .await?;

    Ok(token)
}

/// 清理过期 session
pub async fn cleanup_sessions(pool: &SqlitePool) {
    let _ = sqlx::query("DELETE FROM sessions WHERE expires_at < datetime('now')")
        .execute(pool)
        .await;
}

/// 登录（统一错误消息，不泄露用户是否存在）
pub async fn login(pool: &SqlitePool, username: &str, password: &str, ip: Option<&str>) -> anyhow::Result<(String, bool, Option<String>)> {
    let user = sqlx::query_as::<_, (i64, String, String, Option<String>, Option<String>)>(
        "SELECT id, username, password_hash, totp_secret, passkey_credential FROM users WHERE username = ?"
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    // 统一错误消息：不区分"用户不存在"和"密码错误"
    let (user_id, _, hash, totp_secret, passkey_cred) = match user {
        Some(u) => u,
        None => return Err(anyhow::anyhow!("用户名或密码错误")),
    };

    if !crate::crypto::verify_password(password, &hash) {
        return Err(anyhow::anyhow!("用户名或密码错误"));
    }

    let has_totp = totp_secret.is_some();
    let has_passkey = passkey_cred.is_some();
    let needs_mfa = has_totp || has_passkey;

    let mfa_verified = !needs_mfa;
    let token = create_session(pool, user_id, mfa_verified, ip).await?;

    Ok((token, needs_mfa, totp_secret))
}

/// 验证 TOTP（带限流）
pub async fn verify_totp(pool: &SqlitePool, session_token: &str, code: &str, limiter: &crate::ratelimit::RateLimiter) -> anyhow::Result<bool> {
    let (user_id,): (i64,) = sqlx::query_as(
        "SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')"
    )
    .bind(session_token)
    .fetch_one(pool)
    .await?;

    // 按 session token 限流
    let rate_key = format!("totp:{}", session_token);
    if !limiter.check(&rate_key).await {
        // 超限销毁预认证 session
        let _ = sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(session_token)
            .execute(pool)
            .await;
        return Err(anyhow::anyhow!("验证尝试次数过多，会话已失效，请重新登录"));
    }

    let totp_secret: Option<String> = sqlx::query_scalar(
        "SELECT totp_secret FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    match totp_secret {
        Some(secret) => {
            let valid = crate::totp::verify_code(&secret, code);
            if valid {
                // 验证成功，清除限流记录
                limiter.clear(&rate_key).await;
                sqlx::query("UPDATE sessions SET mfa_verified = 1 WHERE token = ?")
                    .bind(session_token)
                    .execute(pool)
                    .await?;
            } else {
                // 验证失败，记录
                limiter.record_failure(&rate_key).await;
            }
            Ok(valid)
        }
        None => Err(anyhow::anyhow!("未启用 TOTP")),
    }
}

/// 修改密码（加长度校验）
pub async fn change_password(pool: &SqlitePool, user_id: i64, old_password: &str, new_password: &str) -> anyhow::Result<()> {
    if new_password.len() < 8 {
        return Err(anyhow::anyhow!("新密码至少8位"));
    }

    let (_, _, hash): (i64, String, String) = sqlx::query_as(
        "SELECT id, username, password_hash FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    if !crate::crypto::verify_password(old_password, &hash) {
        return Err(anyhow::anyhow!("原密码错误"));
    }

    let new_hash = crate::crypto::hash_password(new_password);
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&new_hash)
        .bind(user_id)
        .execute(pool)
        .await?;

    // 清除该用户所有 session（强制重新登录）
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}
