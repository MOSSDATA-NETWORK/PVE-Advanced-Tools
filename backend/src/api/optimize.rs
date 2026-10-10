//! M6 母机优化与初始化 API：一键初始化、参数优化、状态回采、回滚
use axum::{extract::{Path, State}, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

async fn enqueue(state: &Arc<AppState>, jar: &CookieJar, host_id: i64, spec: crate::jobs::JobSpec, action: &str) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, jar).await;
    match crate::jobs::create_and_enqueue(state, host_id, spec, &actor).await {
        Ok(id) => {
            crate::audit::log(&state.db, &actor, action, Some("host"), Some(host_id), None, None).await;
            Json(json!({"ok": true, "job_id": id}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 批量操作：对全部主机或指定主机列表下发 init/tune
#[derive(Deserialize)]
pub struct BatchRequest {
    pub action: String,
    pub host_ids: Option<Vec<i64>>,
    /// tune 可选：只执行选中的优化项（None = 全部）
    pub items: Option<Vec<String>>,
}

pub async fn batch(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<BatchRequest>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    let hosts = match crate::db::list_hosts(&state.db).await {
        Ok(h) => h,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    let targets: Vec<_> = match &body.host_ids {
        Some(ids) => hosts.into_iter().filter(|h| ids.contains(&h.id)).collect(),
        None => hosts.into_iter().filter(|h| h.host_key_status.as_deref() == Some("confirmed")).collect(),
    };
    let mut results = Vec::new();
    for host in &targets {
        let spec = match body.action.as_str() {
            "init" => crate::tasks::optimize_init(),
            "tune" => match crate::tasks::optimize_tune(body.items.clone()) {
                Ok(s) => s,
                Err(e) => return Json(json!({"ok": false, "error": e})),
            },
            _ => return Json(json!({"ok": false, "error": "action 必须为 init 或 tune"})),
        };
        match crate::jobs::create_and_enqueue(&state, host.id, spec, &actor).await {
            Ok(id) => results.push(json!({"host": host.name, "job_id": id})),
            Err(e) => results.push(json!({"host": host.name, "error": e.to_string()})),
        }
    }
    crate::audit::log(&state.db, &actor, "optimize.batch", None, None,
        Some(&format!("{} × {} 台", body.action, results.len())), None).await;
    Json(json!({"ok": true, "jobs": results}))
}

/// 一键初始化：换 no-subscription 源 + 去订阅弹窗
pub async fn init(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    enqueue(&state, &jar, host_id, crate::tasks::optimize_init(), "optimize.init").await
}

/// 系统更新（dist-upgrade，不可回滚，前端需明确提示）
pub async fn upgrade(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    enqueue(&state, &jar, host_id, crate::tasks::optimize_upgrade(), "optimize.upgrade").await
}

/// 内核参数自适应优化；body 可选 {items: [...]}，缺省全量
#[derive(Deserialize)]
pub struct TuneRequest {
    pub items: Option<Vec<String>>,
}

pub async fn tune(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>, body: Option<Json<TuneRequest>>) -> Json<Value> {
    let items = body.and_then(|b| b.0.items);
    let spec = match crate::tasks::optimize_tune(items) {
        Ok(s) => s,
        Err(e) => return Json(json!({"ok": false, "error": e})),
    };
    enqueue(&state, &jar, host_id, spec, "optimize.tune").await
}

#[derive(Deserialize)]
pub struct RollbackRequest {
    pub component: String,
}

/// 回滚（component = nosub / optimize）
pub async fn rollback(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>, Json(body): Json<RollbackRequest>) -> Json<Value> {
    let Some(spec) = crate::tasks::optimize_rollback(&body.component) else {
        return Json(json!({"ok": false, "error": "component 必须为 nosub 或 optimize"}));
    };
    enqueue(&state, &jar, host_id, spec, "optimize.rollback").await
}

/// 触发状态回采（生成 status 任务，输出在任务详情中查看）
pub async fn status(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    enqueue(&state, &jar, host_id, crate::tasks::optimize_status(), "optimize.status").await
}

/// 最近一次状态任务的结果
pub async fn latest_status(State(state): State<Arc<AppState>>, Path(host_id): Path<i64>) -> Json<Value> {
    let r = sqlx::query_as::<_, (i64, String, Option<chrono::NaiveDateTime>)>(
        "SELECT id, status, finished_at FROM jobs WHERE host_id=? AND kind='optimize.status' ORDER BY id DESC LIMIT 1"
    ).bind(host_id).fetch_optional(&state.db).await;
    match r {
        Ok(Some((job_id, status, finished))) => {
            let out = match sqlx::query_as::<_, (Option<String>,)>(
                "SELECT output FROM job_steps WHERE job_id=? ORDER BY seq DESC LIMIT 1"
            ).bind(job_id).fetch_optional(&state.db).await {
                Ok(o) => o,
                Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
            };
            Json(json!({"ok": true, "job_id": job_id, "status": status, "finished_at": finished,
                "output": out.and_then(|o| o.0)}))
        }
        Ok(None) => Json(json!({"ok": true, "status": "never"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
