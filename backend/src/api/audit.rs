use axum::{extract::{Query, State}, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub action: Option<String>,
    pub actor: Option<String>,
}

/// 审计日志查询（分页 + 按操作/操作者过滤）
pub async fn list(State(state): State<Arc<AppState>>, Query(q): Query<AuditQuery>) -> Json<Value> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);

    let mut sql = String::from("SELECT * FROM audit_log WHERE 1=1");
    let mut count_sql = String::from("SELECT COUNT(*) FROM audit_log WHERE 1=1");
    let mut binds: Vec<String> = vec![];

    if let Some(a) = &q.action {
        if !a.is_empty() {
            // 转义 LIKE 通配符，前缀匹配
            let escaped = a.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
            binds.push(format!("{}%", escaped));
            sql.push_str(&format!(" AND action LIKE ${} ESCAPE '\\'", binds.len()));
            count_sql.push_str(&format!(" AND action LIKE ${} ESCAPE '\\'", binds.len()));
        }
    }
    if let Some(a) = &q.actor {
        if !a.is_empty() {
            binds.push(a.clone());
            sql.push_str(&format!(" AND actor = ${}", binds.len()));
            count_sql.push_str(&format!(" AND actor = ${}", binds.len()));
        }
    }
    sql.push_str(" ORDER BY id DESC");
    binds.push(limit.to_string());
    sql.push_str(&format!(" LIMIT ${}", binds.len()));
    binds.push(offset.to_string());
    sql.push_str(&format!(" OFFSET ${}", binds.len()));

    let mut query = sqlx::query_as::<_, (i64, String, String, Option<String>, Option<String>, Option<String>, Option<String>, Option<chrono::NaiveDateTime>)>(&sql);
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        query = query.bind(b);
    }
    // count 查询只用过滤参数（不含 limit/offset）
    let filter_count = binds.len() - 2;
    for b in binds.iter().take(filter_count) {
        count_q = count_q.bind(b);
    }

    match (query.fetch_all(&state.db).await, count_q.fetch_one(&state.db).await) {
        (Ok(rows), Ok(total)) => {
            let data: Vec<Value> = rows.into_iter().map(|r| json!({
                "id": r.0, "actor": r.1, "action": r.2, "target_type": r.3,
                "target_id": r.4, "detail": r.5, "ip": r.6, "created_at": r.7,
            })).collect();
            Json(json!({"ok": true, "data": data, "total": total}))
        }
        (Err(e), _) | (_, Err(e)) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
