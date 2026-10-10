//! 审计日志模块
//! 记录「谁在什么时候对哪台主机做了什么」。写入失败只记日志不阻断业务，
//! 但危险操作（删除主机、更新、任务下发）的调用方应在写库前先写审计。
use sqlx::SqlitePool;

pub async fn log(
    pool: &SqlitePool,
    actor: &str,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<i64>,
    detail: Option<&str>,
    ip: Option<&str>,
) {
    let target_id = target_id.map(|v| v.to_string());
    let r = sqlx::query(
        "INSERT INTO audit_log (actor, action, target_type, target_id, detail, ip) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(actor)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(detail)
    .bind(ip)
    .execute(pool)
    .await;
    if let Err(e) = r {
        tracing::error!("审计日志写入失败 actor={} action={}: {}", actor, action, e);
    }
}

/// 从 session cookie 解析当前用户名，用于审计 actor
pub async fn actor_from_cookie(pool: &SqlitePool, jar: &axum_extra::extract::CookieJar) -> String {
    let Some(cookie) = jar.get("session") else {
        return "anonymous".to_string();
    };
    let token = cookie.value();
    sqlx::query_scalar::<_, String>(
        "SELECT u.username FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token = ? AND s.expires_at > datetime('now')"
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "unknown".to_string())
}
