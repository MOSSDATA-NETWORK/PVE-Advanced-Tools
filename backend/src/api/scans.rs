use axum::{extract::{Path, Query, State}, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::{AppState, db};

#[derive(Deserialize)]
pub struct CreateScanRequest {
    pub host_id: Option<i64>,
}

#[derive(Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list(State(state): State<Arc<AppState>>, Query(params): Query<ListParams>) -> Json<Value> {
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);

    let scans = db::list_scans(&state.db, limit, offset).await;
    let total = db::count_scans(&state.db).await;

    match (scans, total) {
        (Ok(scans), Ok(total)) => Json(json!({
            "ok": true,
            "data": scans,
            "total": total,
            "limit": limit,
            "offset": offset,
        })),
        (Err(e), _) | (_, Err(e)) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn get(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    match sqlx::query_as::<_, db::Scan>("SELECT * FROM scans WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(scan)) => Json(json!({"ok": true, "data": scan})),
        Ok(None) => Json(json!({"ok": false, "error": "扫描不存在"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn create(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<CreateScanRequest>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    let scan = match db::create_scan(&state.db, body.host_id).await {
        Ok(s) => s,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };

    crate::audit::log(&state.db, &actor, "scan.create", Some("scan"), Some(scan.id),
        body.host_id.map(|h| format!("host_id={}", h)).as_deref(), None).await;

    let state_clone = state.clone();
    let scan_id = scan.id;
    let host_id = body.host_id;
    tokio::spawn(async move {
        if let Err(e) = crate::detect::run_scan(state_clone, scan_id, host_id).await {
            tracing::error!("Scan {} failed: {}", scan_id, e);
        }
    });

    Json(json!({"ok": true, "data": scan, "message": "扫描已启动"}))
}

pub async fn stop(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    // 将扫描状态标记为 stopped，检测循环会检查此状态并退出
    match sqlx::query("UPDATE scans SET status='stopped', completed_at=CURRENT_TIMESTAMP WHERE id=? AND status='running'")
        .bind(id)
        .execute(&state.db)
        .await
    {
        Ok(r) => {
            if r.rows_affected() > 0 {
                Json(json!({"ok": true, "message": "扫描已停止"}))
            } else {
                Json(json!({"ok": false, "error": "扫描不存在或未在运行"}))
            }
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
