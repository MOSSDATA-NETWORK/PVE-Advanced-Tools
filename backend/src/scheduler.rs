use std::sync::Arc;
use tokio_cron_scheduler::{Job, JobScheduler};
use crate::AppState;

pub async fn start(state: Arc<AppState>) -> anyhow::Result<()> {
    let mut sched = JobScheduler::new().await?;

    // Check schedules every minute
    let state_clone = state.clone();
    let job = Job::new("0 * * * * *", move |_, _| {
        let state = state_clone.clone();
        tokio::spawn(async move {
            if let Err(e) = check_and_run_schedules(state).await {
                tracing::error!("Scheduler check failed: {}", e);
            }
        });
    })?;

    sched.add(job).await?;

    // 巡检：每 5 分钟检查一次是否到点（间隔可在面板设置）
    let inspect_state = state.clone();
    let inspect_job = Job::new("0 */5 * * * *", move |_, _| {
        let state = inspect_state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_due_inspections(state).await {
                tracing::error!("Inspection tick failed: {}", e);
            }
        });
    })?;
    sched.add(inspect_job).await?;
    sched.start().await?;

    tracing::info!("Scheduler started");
    Ok(())
}

/// 到点巡检：对已确认指纹的主机按间隔下发巡检任务
async fn run_due_inspections(state: Arc<AppState>) -> anyhow::Result<()> {
    let enabled: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key='inspect_enabled'")
        .fetch_optional(&state.db).await.unwrap_or(None);
    if enabled.as_deref() == Some("0") {
        return Ok(());
    }
    let interval: i64 = match sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key='inspect_interval_mins'")
        .fetch_optional(&state.db).await
    {
        Ok(Some(v)) => v.parse().unwrap_or(60),
        _ => 60,
    };

    let hosts = crate::db::list_hosts(&state.db).await?;
    for host in hosts {
        if host.host_key_status.as_deref() != Some("confirmed") {
            continue;
        }
        // 距上次巡检超过间隔才再发（无巡检记录则立即）
        let last: Option<chrono::NaiveDateTime> = sqlx::query_scalar(
            "SELECT created_at FROM jobs WHERE host_id=? AND kind='inspect.host' ORDER BY id DESC LIMIT 1"
        ).bind(host.id).fetch_optional(&state.db).await.unwrap_or(None);
        let due = match last {
            Some(t) => (chrono::Utc::now().naive_utc() - t).num_minutes() >= interval,
            None => true,
        };
        if !due {
            continue;
        }
        match crate::tasks::inspect_host(&state, host.id).await {
            Ok(spec) => {
                if let Err(e) = crate::jobs::create_and_enqueue(&state, host.id, spec, "system").await {
                    tracing::warn!("巡检任务创建失败 host={}: {}", host.name, e);
                }
            }
            Err(e) => tracing::warn!("巡检任务构建失败 host={}: {}", host.name, e),
        }
    }
    Ok(())
}

async fn check_and_run_schedules(state: Arc<AppState>) -> anyhow::Result<()> {
    let schedules = crate::db::list_schedules(&state.db).await?;
    let now = chrono::Utc::now().naive_utc();

    for schedule in &schedules {
        if !schedule.enabled { continue; }

        // 解析 cron 表达式：支持标准 5 段（分 时 日 月 周，补 0 秒）与含秒的 6/7 段
        let cron = match parse_cron(&schedule.cron_expr) {
            Some(c) => c,
            None => {
                tracing::warn!("计划 {} 的 cron 表达式无法解析，已跳过: {}", schedule.id, schedule.cron_expr);
                continue;
            }
        };
        let compute_next = |from: chrono::DateTime<chrono::Utc>| cron.after(&from).next().map(|d| d.naive_utc());

        // next_run 只在缺失（新建/未初始化）时预计算并落库；
        // 已存在时以库内值为准——过期即视为到点触发（重启、停机错过的触发也能补上）
        let next = match schedule.next_run {
            Some(t) => t,
            None => match compute_next(chrono::Utc::now()) {
                Some(t) => {
                    sqlx::query("UPDATE schedules SET next_run=? WHERE id=?")
                        .bind(t).bind(schedule.id).execute(&state.db).await?;
                    continue;
                }
                None => continue,
            },
        };

        if now < next {
            continue;
        }

        tracing::info!("Running scheduled scan for host {:?}", schedule.host_id);
        let scan = crate::db::create_scan(&state.db, schedule.host_id).await?;
        let state_clone = state.clone();
        let scan_id = scan.id;
        let host_id = schedule.host_id;

        tokio::spawn(async move {
            if let Err(e) = crate::detect::run_scan(state_clone, scan_id, host_id).await {
                tracing::error!("Scheduled scan {} failed: {}", scan_id, e);
            }
        });

        let following = compute_next(chrono::Utc::now());
        sqlx::query("UPDATE schedules SET last_run=CURRENT_TIMESTAMP, next_run=? WHERE id=?")
            .bind(following).bind(schedule.id).execute(&state.db).await?;
    }

    Ok(())
}

/// 归一化 cron 表达式：5 段标准格式补 0 秒前缀；6/7 段原样。解析失败返回 None
fn parse_cron(expr: &str) -> Option<cron::Schedule> {
    let fields = expr.split_whitespace().count();
    let normalized = if fields == 5 {
        format!("0 {}", expr.trim())
    } else {
        expr.trim().to_string()
    };
    normalized.parse().ok()
}
