use axum::{extract::{Path, State}, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

/// 主机 VM 清单（含稳定标识状态）
pub async fn list(State(state): State<Arc<AppState>>, Path(host_id): Path<i64>) -> Json<Value> {
    let r = sqlx::query_as::<_, crate::vms::Vm>(
        "SELECT * FROM vms WHERE host_id = ? ORDER BY vmid"
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await;
    match r {
        Ok(vms) => Json(json!({"ok": true, "data": vms})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 触发 VM 清单同步（抓取 SMBIOS UUID，检测重绑定）
pub async fn sync(State(state): State<Arc<AppState>>, Path(host_id): Path<i64>) -> Json<Value> {
    match crate::vms::sync_vms(&state, host_id).await {
        Ok(report) => Json(json!({"ok": true, "data": report})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 标识变更事件（迁移/克隆/复用串扰审计线索）
pub async fn events(State(state): State<Arc<AppState>>, Path(host_id): Path<i64>) -> Json<Value> {
    let r = sqlx::query_as::<_, (i64, i64, i64, Option<String>, Option<String>, String, Option<chrono::NaiveDateTime>)>(
        "SELECT * FROM vm_identity_events WHERE host_id = ? ORDER BY id DESC LIMIT 200"
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await;
    match r {
        Ok(rows) => {
            let data: Vec<Value> = rows.into_iter().map(|r| json!({
                "id": r.0, "host_id": r.1, "vmid": r.2, "old_uuid": r.3,
                "new_uuid": r.4, "reason": r.5, "created_at": r.6,
            })).collect();
            Json(json!({"ok": true, "data": data}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
