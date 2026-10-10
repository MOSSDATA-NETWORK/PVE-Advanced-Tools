use axum::{extract::{Path, Query, State}, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub host_id: Option<i64>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// 任务列表
pub async fn list(State(state): State<Arc<AppState>>, Query(q): Query<ListQuery>) -> Json<Value> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    match crate::jobs::list_jobs(&state.db, q.host_id, q.status.as_deref(), limit, offset).await {
        Ok(jobs) => Json(json!({"ok": true, "data": jobs})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 任务详情（含步骤与输出）
pub async fn get(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    match crate::jobs::get_job_with_steps(&state.db, id).await {
        Ok((job, steps)) => Json(json!({"ok": true, "data": {"job": job, "steps": steps}})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 在指定主机上创建并下发任务
pub async fn create_on_host(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(host_id): Path<i64>,
    Json(spec): Json<crate::jobs::JobSpec>,
) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    match crate::jobs::create_and_enqueue(&state, host_id, spec, &actor).await {
        Ok(id) => Json(json!({"ok": true, "data": {"id": id}})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 重跑失败/已回滚/被放弃的任务（从检查点续跑）
pub async fn retry(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    match crate::jobs::retry_job(&state, id, &actor).await {
        Ok(_) => Json(json!({"ok": true, "message": "任务已重新入队"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
