//! 告警引擎（M7）：规则判定 + 历史落库 + 通知下发
//! 触发类型：host_offline / job_failed / resource_high / inspect_failed
//! 30 分钟内同类型+同主机+同标题去重，避免告警轰炸
use std::sync::Arc;

use crate::AppState;

/// 触发告警：写历史，命中启用规则则发通知
pub async fn raise(
    state: &Arc<AppState>,
    trigger_type: &str,
    level: &str,
    title: &str,
    message: &str,
    host_id: Option<i64>,
) {
    // 去重：BEGIN IMMEDIATE 事务内查重+写入（立即取写锁，防并发锁升级失败丢告警）
    let mut conn = match state.db.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("告警连接获取失败: {}", e);
            return;
        }
    };
    if let Err(e) = sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await {
        tracing::error!("告警事务开启失败: {}", e);
        return;
    }
    let dup: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_history WHERE title=? AND COALESCE(host_id,0)=COALESCE(?,0) \
         AND created_at > datetime('now', '-30 minutes')"
    )
    .bind(title).bind(host_id)
    .fetch_one(&mut *conn)
    .await
    .unwrap_or(1);
    if dup > 0 {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return;
    }

    // 命中启用规则才通知（无规则时仍留历史）
    let rule: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM alert_rules WHERE trigger_type=? AND enabled=1 LIMIT 1"
    )
    .bind(trigger_type)
    .fetch_optional(&mut *conn)
    .await
    .unwrap_or(None);

    let rule_id = rule.map(|r| r.0);
    let r = sqlx::query(
        "INSERT INTO alert_history (rule_id, level, title, message, host_id, notified) VALUES (?, ?, ?, ?, ?, 0)"
    )
    .bind(rule_id).bind(level).bind(title).bind(message).bind(host_id)
    .execute(&mut *conn)
    .await;
    let alert_id = match r {
        Ok(res) => res.last_insert_rowid(),
        Err(e) => {
            tracing::error!("告警写入失败: {}", e);
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return;
        }
    };
    if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
        tracing::error!("告警提交失败: {}", e);
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return;
    }

    if rule_id.is_some() {
        // 至少一个渠道送达才标记已通知
        let sent = crate::notify::send_alert(&state.db, &state.master_key, title, message).await;
        if sent > 0 {
            let _ = sqlx::query("UPDATE alert_history SET notified=1 WHERE id=?")
                .bind(alert_id).execute(&state.db).await;
        }
    }
}

/// 任务结束钩子（jobs.rs 调用，仅 failed 终态触发）：失败任务按类型触发告警
pub async fn on_job_finished(state: &Arc<AppState>, job: &crate::jobs::Job, failed: bool) {
    if !failed {
        return;
    }
    let host_name = crate::db::get_host(&state.db, job.host_id)
        .await
        .map(|h| h.name)
        .unwrap_or_else(|_| format!("#{}", job.host_id));
    let err = job.error.as_deref().unwrap_or("");

    match job.kind.as_str() {
        "inspect.host" => {
            raise(state, "host_offline", "critical",
                &format!("巡检失败：{}", host_name),
                &format!("节点离线或巡检执行失败。{}", err), Some(job.host_id)).await;
        }
        k if k.starts_with("netguard.") || k.starts_with("arpfilter.") || k.starts_with("optimize.") => {
            raise(state, "job_failed", "warning",
                &format!("任务失败：{} ({})", k, host_name),
                err, Some(job.host_id)).await;
        }
        _ => {}
    }
}

/// 巡检输出评估：解析机器可读行，超阈值触发 resource_high；组件失活触发 inspect_failed
pub async fn evaluate_inspection(state: &Arc<AppState>, job: &crate::jobs::Job, steps: &[crate::jobs::JobStep]) {
    let output: String = steps.iter()
        .filter_map(|s| s.output.as_deref())
        .collect::<Vec<_>>()
        .join("\n");

    let threshold: i64 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT threshold FROM alert_rules WHERE trigger_type='resource_high' AND enabled=1 LIMIT 1), 90)"
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(90);

    let host_name = crate::db::get_host(&state.db, job.host_id)
        .await
        .map(|h| h.name)
        .unwrap_or_else(|_| format!("#{}", job.host_id));

    for line in output.lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        match key.trim() {
            "DISK" | "MEM" => {
                if let Ok(pct) = val.trim().parse::<i64>() {
                    if pct >= threshold {
                        let what = if key.trim() == "DISK" { "磁盘" } else { "内存" };
                        raise(state, "resource_high", "warning",
                            &format!("{}使用率告警：{}", what, host_name),
                            &format!("{} 使用率达 {}%（阈值 {}%）", what, pct, threshold), Some(job.host_id)).await;
                    }
                }
            }
            "DEAD" => {
                raise(state, "inspect_failed", "critical",
                    &format!("管控组件失效：{}", host_name),
                    &format!("组件 {} 已安装但服务未运行", val.trim()), Some(job.host_id)).await;
            }
            _ => {}
        }
    }
}
