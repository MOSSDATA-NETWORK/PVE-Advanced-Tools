//! 总览仪表盘聚合端点：集群概览 + 待办事项（大纲「总览」）
use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

pub async fn overview(State(state): State<Arc<AppState>>) -> Json<Value> {
    let db = &state.db;
    async fn count(db: &sqlx::SqlitePool, sql: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(sql).fetch_one(db).await.unwrap_or(0)
    }

    let total_hosts = count(db, "SELECT COUNT(*) FROM hosts").await;
    let online_hosts = count(db, "SELECT COUNT(*) FROM hosts WHERE status='online'").await;
    let total_vms = count(db, "SELECT COUNT(*) FROM vms WHERE status != 'deleted'").await;
    let active_threats = count(db, "SELECT COUNT(*) FROM results WHERE status IN ('detected','confirmed')").await;
    let alerts_24h = count(db, "SELECT COUNT(*) FROM alert_history WHERE created_at > datetime('now', '-1 day')").await;
    let running_jobs = count(db, "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')").await;
    let failed_jobs_24h = count(db, "SELECT COUNT(*) FROM jobs WHERE status IN ('failed','rollback_failed') AND created_at > datetime('now', '-1 day')").await;

    // QoS 节点状态（推断值，口径与 qos::infer_node_status 一致）
    let mut qos = json!({"fresh": 0, "degraded": 0, "stale": 0});
    let rows = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT last_snapshot_at, last_error FROM qos_node_status"
    ).fetch_all(db).await.unwrap_or_default();
    for (snap, err) in rows {
        let t = snap.and_then(|s| chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S").ok());
        let st = crate::qos::infer_node_status(t, &err);
        let key = match st { "fresh" => "fresh", "degraded" => "degraded", _ => "stale" };
        qos[key] = json!(qos[key].as_i64().unwrap_or(0) + 1);
    }

    // 待办：离线/未确认主机
    let todo_hosts = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT id, name, status FROM hosts WHERE status != 'online' OR host_key_status != 'confirmed' ORDER BY id"
    ).fetch_all(db).await.unwrap_or_default();
    // 待办：最近失败任务
    let todo_jobs = sqlx::query_as::<_, (i64, i64, String, Option<String>)>(
        "SELECT id, host_id, kind, error FROM jobs WHERE status IN ('failed','rollback_failed') ORDER BY id DESC LIMIT 5"
    ).fetch_all(db).await.unwrap_or_default();
    // 待办：最近告警（组件失效/资源水位等）
    let todo_alerts = sqlx::query_as::<_, (i64, String, String, Option<i64>, Option<String>)>(
        "SELECT id, level, title, host_id, created_at FROM alert_history ORDER BY id DESC LIMIT 5"
    ).fetch_all(db).await.unwrap_or_default();

    Json(json!({"ok": true, "data": {
        "total_hosts": total_hosts,
        "online_hosts": online_hosts,
        "total_vms": total_vms,
        "active_threats": active_threats,
        "alerts_24h": alerts_24h,
        "running_jobs": running_jobs,
        "failed_jobs_24h": failed_jobs_24h,
        "qos": qos,
        "todos": {
            "hosts": todo_hosts.iter().map(|(id, name, st)| json!({"id": id, "name": name, "status": st})).collect::<Vec<_>>(),
            "jobs": todo_jobs.iter().map(|(id, hid, kind, err)| json!({"id": id, "host_id": hid, "kind": kind, "error": err})).collect::<Vec<_>>(),
            "alerts": todo_alerts.iter().map(|(id, level, title, hid, at)| json!({"id": id, "level": level, "title": title, "host_id": hid, "created_at": at})).collect::<Vec<_>>(),
        }
    }}))
}
