//! M7 告警规则 / 告警历史 / 巡检设置 API
use axum::{extract::{Path, Query, State}, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

const TRIGGER_TYPES: [&str; 4] = ["host_offline", "job_failed", "resource_high", "inspect_failed"];

// ---- 告警规则 ----

pub async fn list_rules(State(state): State<Arc<AppState>>) -> Json<Value> {
    let r = sqlx::query_as::<_, (i64, String, String, Option<i64>, bool)>(
        "SELECT id, name, trigger_type, threshold, enabled FROM alert_rules ORDER BY id"
    ).fetch_all(&state.db).await;
    match r {
        Ok(rows) => Json(json!({"ok": true, "data": rows.iter().map(|r| json!({
            "id": r.0, "name": r.1, "trigger_type": r.2, "threshold": r.3, "enabled": r.4
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct RuleRequest {
    pub name: String,
    pub trigger_type: String,
    pub threshold: Option<i64>,
    pub enabled: Option<bool>,
}

pub async fn create_rule(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<RuleRequest>) -> Json<Value> {
    if !TRIGGER_TYPES.contains(&body.trigger_type.as_str()) {
        return Json(json!({"ok": false, "error": "未知触发类型"}));
    }
    if body.name.is_empty() || body.name.len() > 64 {
        return Json(json!({"ok": false, "error": "名称无效"}));
    }
    if let Some(t) = body.threshold {
        if !(1..=100).contains(&t) {
            return Json(json!({"ok": false, "error": "阈值须在 1-100 之间"}));
        }
    }
    let r = sqlx::query("INSERT INTO alert_rules (name, trigger_type, threshold, enabled) VALUES (?, ?, ?, ?)")
        .bind(&body.name).bind(&body.trigger_type).bind(body.threshold).bind(body.enabled.unwrap_or(true))
        .execute(&state.db).await;
    match r {
        Ok(_) => {
            let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
            crate::audit::log(&state.db, &actor, "alert.rule_add", None, None, Some(&body.name), None).await;
            Json(json!({"ok": true}))
        }
        Err(e) if e.to_string().contains("UNIQUE") => {
            Json(json!({"ok": false, "error": "该触发类型已有规则（每种类型仅一条），请编辑现有规则"}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn toggle_rule(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let r = sqlx::query("UPDATE alert_rules SET enabled = NOT enabled, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(id).execute(&state.db).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn delete_rule(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let r = sqlx::query("DELETE FROM alert_rules WHERE id=?").bind(id).execute(&state.db).await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ---- 告警历史 ----

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn history(State(state): State<Arc<AppState>>, Query(q): Query<HistoryQuery>) -> Json<Value> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let rows = sqlx::query_as::<_, (i64, Option<i64>, String, String, Option<String>, Option<i64>, bool, Option<chrono::NaiveDateTime>)>(
        "SELECT id, rule_id, level, title, message, host_id, notified, created_at FROM alert_history ORDER BY id DESC LIMIT ? OFFSET ?"
    ).bind(limit).bind(offset).fetch_all(&state.db).await;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alert_history").fetch_one(&state.db).await.unwrap_or(0);
    match rows {
        Ok(rows) => Json(json!({"ok": true, "total": total, "data": rows.iter().map(|r| json!({
            "id": r.0, "rule_id": r.1, "level": r.2, "title": r.3, "message": r.4,
            "host_id": r.5, "notified": r.6, "created_at": r.7
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// ---- 巡检设置与手动触发 ----

pub async fn get_inspect_settings(State(state): State<Arc<AppState>>) -> Json<Value> {
    let enabled: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key='inspect_enabled'")
        .fetch_optional(&state.db).await.unwrap_or(None);
    let interval: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key='inspect_interval_mins'")
        .fetch_optional(&state.db).await.unwrap_or(None);
    Json(json!({"ok": true,
        "enabled": enabled.as_deref() != Some("0"),
        "interval_mins": interval.and_then(|v| v.parse::<i64>().ok()).unwrap_or(60),
    }))
}

#[derive(Deserialize)]
pub struct InspectSettings {
    pub enabled: bool,
    pub interval_mins: i64,
}

pub async fn put_inspect_settings(State(state): State<Arc<AppState>>, Json(body): Json<InspectSettings>) -> Json<Value> {
    if !(15..=1440).contains(&body.interval_mins) {
        return Json(json!({"ok": false, "error": "巡检周期须在 15-1440 分钟之间"}));
    }
    let r = async {
        let mut tx = state.db.begin().await?;
        sqlx::query("INSERT INTO settings (key, value, updated_at) VALUES ('inspect_enabled', ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP")
            .bind(if body.enabled { "1" } else { "0" }).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO settings (key, value, updated_at) VALUES ('inspect_interval_mins', ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP")
            .bind(body.interval_mins.to_string()).execute(&mut *tx).await?;
        tx.commit().await
    }.await;
    match r {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"ok": false, "error": format!("保存失败: {}", e)})),
    }
}

/// 手动触发一台主机巡检
pub async fn inspect_now(State(state): State<Arc<AppState>>, jar: CookieJar, Path(host_id): Path<i64>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    match crate::tasks::inspect_host(&state, host_id).await {
        Ok(spec) => match crate::jobs::create_and_enqueue(&state, host_id, spec, &actor).await {
            Ok(id) => Json(json!({"ok": true, "job_id": id})),
            Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
        },
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}
