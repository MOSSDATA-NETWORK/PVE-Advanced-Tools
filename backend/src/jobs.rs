//! SSH 作业器：任务下发 / 结果回采框架（P0 冻结规格）
//! - 任务包签名：HMAC-SHA256（master_key 派生密钥），执行前校验，防篡改防重放
//! - 步骤化 + 检查点：已完成步骤跳过，失败可从检查点续跑；
//!   声明为不可安全重跑（rerun_safe=false）的步骤失败后必须先回滚
//! - 失败策略按任务分类：fail_open（ARP 降噪类，故障时保持网络开放）/
//!   fail_closed（管控、限速、优化类，失败即回滚已完成的步骤）
//! - 同一主机任务串行（主机锁）；排队超过 queue_ttl_secs 自动放弃
//! - 结果绑定 job id + 每主机单调 seq；执行前强制主机密钥指纹已确认
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::AppState;

pub const POLICY_FAIL_OPEN: &str = "fail_open";
pub const POLICY_FAIL_CLOSED: &str = "fail_closed";

/// 步骤输出截断上限，避免把数据库撑爆
const MAX_OUTPUT_BYTES: usize = 8192;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepSpec {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub rollback_command: Option<String>,
    /// 失败后是否可安全重跑该步（幂等）
    #[serde(default = "default_true")]
    pub rerun_safe: bool,
}

fn default_true() -> bool { true }
fn default_timeout() -> i64 { 300 }
fn default_queue_ttl() -> i64 { 1800 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    pub kind: String,
    pub failure_policy: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: i64,
    #[serde(default = "default_queue_ttl")]
    pub queue_ttl_secs: i64,
    pub steps: Vec<StepSpec>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Job {
    pub id: i64,
    pub host_id: i64,
    pub kind: String,
    pub payload: String,
    pub signature: String,
    pub seq: i64,
    pub status: String,
    pub failure_policy: String,
    pub checkpoint_step: i64,
    pub timeout_secs: i64,
    pub queue_ttl_secs: i64,
    pub error: Option<String>,
    pub created_by: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub started_at: Option<NaiveDateTime>,
    pub finished_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct JobStep {
    pub id: i64,
    pub job_id: i64,
    pub seq: i64,
    pub name: String,
    pub command: String,
    pub rollback_command: Option<String>,
    pub rerun_safe: bool,
    pub status: String,
    pub output: Option<String>,
    pub exit_code: Option<i64>,
    pub started_at: Option<NaiveDateTime>,
    pub finished_at: Option<NaiveDateTime>,
}

/// 每主机串行锁（进程内）
#[derive(Default)]
pub struct HostLocks(pub Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>);

impl HostLocks {
    pub fn get(&self, host_id: i64) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.0.lock().unwrap();
        map.entry(host_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

/// 签名密钥：master_key 派生，避免与加密密钥混用
fn signing_key(master_key: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"pve-at-job-signing-v1");
    h.update(master_key);
    h.finalize().to_vec()
}

/// 任务包签名输入：host_id + seq + 规格规范化 JSON（含全部执行参数）
fn canonical_payload(host_id: i64, seq: i64, spec: &JobSpec) -> String {
    serde_json::json!({
        "host_id": host_id,
        "seq": seq,
        "kind": spec.kind,
        "failure_policy": spec.failure_policy,
        "timeout_secs": spec.timeout_secs,
        "queue_ttl_secs": spec.queue_ttl_secs,
        "steps": spec.steps,
    })
    .to_string()
}

/// 执行参数以签名载荷为唯一来源：数据库行被篡改时签名校验失败，拒绝执行
#[derive(Debug, Deserialize)]
struct SignedPayload {
    host_id: i64,
    seq: i64,
    kind: String,
    failure_policy: String,
    timeout_secs: i64,
    queue_ttl_secs: i64,
    steps: Vec<StepSpec>,
}

fn validate_spec(spec: &JobSpec) -> anyhow::Result<()> {
    if spec.kind.is_empty() || spec.kind.len() > 64 {
        return Err(anyhow::anyhow!("任务类型无效"));
    }
    if spec.failure_policy != POLICY_FAIL_OPEN && spec.failure_policy != POLICY_FAIL_CLOSED {
        return Err(anyhow::anyhow!("失败策略必须为 fail_open 或 fail_closed"));
    }
    if spec.steps.is_empty() || spec.steps.len() > 64 {
        return Err(anyhow::anyhow!("任务步骤数量无效"));
    }
    if !(10..=86400).contains(&spec.timeout_secs) {
        return Err(anyhow::anyhow!("超时时间须在 10-86400 秒之间"));
    }
    if !(60..=604800).contains(&spec.queue_ttl_secs) {
        return Err(anyhow::anyhow!("排队 TTL 须在 60-604800 秒之间"));
    }
    for s in &spec.steps {
        // 命令上限 64KB：容纳 base64 内嵌的脚本上传步骤
        if s.name.is_empty() || s.name.len() > 128 || s.command.is_empty() || s.command.len() > 65536 {
            return Err(anyhow::anyhow!("步骤名称或命令无效"));
        }
        if let Some(rb) = &s.rollback_command {
            if rb.is_empty() || rb.len() > 65536 {
                return Err(anyhow::anyhow!("回滚命令无效"));
            }
        }
    }
    Ok(())
}

/// 创建任务并异步入队执行，返回任务 ID
pub async fn create_and_enqueue(
    state: &Arc<AppState>,
    host_id: i64,
    spec: JobSpec,
    actor: &str,
) -> anyhow::Result<i64> {
    validate_spec(&spec)?;
    // 主机存在性校验
    crate::db::get_host(&state.db, host_id).await?;

    // 事务：序号分配与任务+步骤写入原子完成，避免并发序号冲突或半截任务
    let mut tx = state.db.begin().await?;

    let seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) + 1 FROM jobs WHERE host_id = ?")
        .bind(host_id)
        .fetch_one(&mut *tx)
        .await?;

    let payload = canonical_payload(host_id, seq, &spec);
    let signature = crate::crypto::hmac_sha256_hex(&signing_key(&state.master_key), payload.as_bytes());

    let job_id = sqlx::query(
        "INSERT INTO jobs (host_id, kind, payload, signature, seq, failure_policy, timeout_secs, queue_ttl_secs, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(host_id)
    .bind(&spec.kind)
    .bind(&payload)
    .bind(&signature)
    .bind(seq)
    .bind(&spec.failure_policy)
    .bind(spec.timeout_secs)
    .bind(spec.queue_ttl_secs)
    .bind(actor)
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();

    for (i, step) in spec.steps.iter().enumerate() {
        sqlx::query(
            "INSERT INTO job_steps (job_id, seq, name, command, rollback_command, rerun_safe) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(job_id)
        .bind((i + 1) as i64)
        .bind(&step.name)
        .bind(&step.command)
        .bind(&step.rollback_command)
        .bind(step.rerun_safe)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    crate::audit::log(
        &state.db, actor, "job.create", Some("host"), Some(host_id),
        Some(&format!("job_id={} kind={} seq={}", job_id, spec.kind, seq)), None,
    ).await;

    let state2 = state.clone();
    tokio::spawn(async move {
        run_locked(state2, job_id).await;
    });
    Ok(job_id)
}

async fn run_locked(state: Arc<AppState>, job_id: i64) {
    let host_id: i64 = match sqlx::query_scalar("SELECT host_id FROM jobs WHERE id = ?")
        .bind(job_id)
        .fetch_one(&state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Job {} 加载失败: {}", job_id, e);
            return;
        }
    };
    let lock = state.job_locks.get(host_id);
    let _guard = lock.lock().await;
    if let Err(e) = run_job(&state, job_id).await {
        tracing::error!("Job {} 执行异常: {}", job_id, e);
        let _ = sqlx::query("UPDATE jobs SET status='failed', error=?, finished_at=CURRENT_TIMESTAMP WHERE id=? AND status='running'")
            .bind(format!("内部错误: {}", e))
            .bind(job_id)
            .execute(&state.db)
            .await;
    }

    // 任务终态钩子：失败告警 + 巡检结果评估
    if let Ok((job, steps)) = get_job_with_steps(&state.db, job_id).await {
        match job.status.as_str() {
            "succeeded" => {
                if job.kind == "inspect.host" {
                    crate::alerts::evaluate_inspection(&state, &job, &steps).await;
                }
            }
            // abandoned = 排队超时（节点可能正常），不当作执行失败告警
            "failed" | "rolled_back" => crate::alerts::on_job_finished(&state, &job, true).await,
            _ => {}
        }
    }
}

/// 执行任务主体（调用方须已持有主机锁）
async fn run_job(state: &Arc<AppState>, job_id: i64) -> anyhow::Result<()> {
    let job = sqlx::query_as::<_, Job>("SELECT * FROM jobs WHERE id = ?")
        .bind(job_id)
        .fetch_one(&state.db)
        .await?;

    // 防重放：只有 queued 状态可进入执行
    if job.status != "queued" {
        return Ok(());
    }

    // 签名校验：任务包在库中被篡改则拒绝执行
    if !crate::crypto::hmac_sha256_verify(&signing_key(&state.master_key), job.payload.as_bytes(), &job.signature) {
        set_job_status(&state.db, job_id, "failed", Some("任务签名校验失败")).await;
        return Ok(());
    }

    // 执行参数以签名载荷为唯一来源（防数据库篡改执行策略）
    let signed: SignedPayload = match serde_json::from_str(&job.payload) {
        Ok(s) => s,
        Err(_) => {
            set_job_status(&state.db, job_id, "failed", Some("任务载荷解析失败")).await;
            return Ok(());
        }
    };
    if signed.host_id != job.host_id || signed.seq != job.seq || signed.kind != job.kind {
        set_job_status(&state.db, job_id, "failed", Some("任务载荷与记录不一致")).await;
        return Ok(());
    }

    // 排队超时放弃（TTL 以签名载荷为准）
    if let Some(created) = job.created_at {
        let age = chrono::Utc::now().naive_utc() - created;
        if age.num_seconds() > signed.queue_ttl_secs {
            set_job_status(&state.db, job_id, "abandoned", Some("排队超时，自动放弃")).await;
            return Ok(());
        }
    }

    let host = crate::db::get_host(&state.db, job.host_id).await?;

    // 主机密钥指纹未确认 → 拒绝执行（防中间人）
    if host.host_key_status.as_deref() != Some("confirmed") {
        set_job_status(&state.db, job_id, "failed", Some("主机密钥指纹未确认，请先在主机详情中确认指纹")).await;
        return Ok(());
    }

    let steps = sqlx::query_as::<_, JobStep>("SELECT * FROM job_steps WHERE job_id = ? ORDER BY seq")
        .bind(job_id)
        .fetch_all(&state.db)
        .await?;

    // 步骤表必须与签名载荷一致（含 seq，防篡改步骤内容/顺序/检查点）
    if steps.len() != signed.steps.len()
        || !steps.iter().zip(signed.steps.iter()).enumerate().all(|(i, (row, spec))| {
            row.seq == (i + 1) as i64
                && row.name == spec.name
                && row.command == spec.command
                && row.rollback_command == spec.rollback_command
                && row.rerun_safe == spec.rerun_safe
        })
    {
        set_job_status(&state.db, job_id, "failed", Some("步骤记录与签名载荷不一致")).await;
        return Ok(());
    }

    set_job_running(&state.db, job_id).await;

    let auth = crate::deploy::SshAuth::from_host(
        host.password_encrypted.as_deref(),
        host.ssh_key_encrypted.as_deref(),
        &state.master_key,
    )?;
    let kh = Some(state.known_hosts_path.as_str());

    for step in &steps {
        if step.status == "succeeded" {
            continue; // 检查点续跑：跳过已完成步骤
        }

        set_step_running(&state.db, step.id).await;
        let exec = crate::deploy::ssh_exec_kh(
            &host.host, host.port as u16, &host.username, &auth, &step.command, kh,
        );
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(signed.timeout_secs as u64),
            exec,
        ).await;

        match result {
            Ok(Ok(output)) => {
                finish_step(&state.db, step.id, "succeeded", Some(&output), Some(0)).await;
                sqlx::query("UPDATE jobs SET checkpoint_step=? WHERE id=?")
                    .bind(step.seq).bind(job_id).execute(&state.db).await?;
            }
            Ok(Err(e)) => {
                finish_step(&state.db, step.id, "failed", Some(&e.to_string()), None).await;
                return handle_step_failure(state, &job, &signed, &steps, step, &e.to_string()).await;
            }
            Err(_) => {
                let msg = format!("步骤超时（{}秒）", signed.timeout_secs);
                finish_step(&state.db, step.id, "failed", Some(&msg), None).await;
                return handle_step_failure(state, &job, &signed, &steps, step, &msg).await;
            }
        }
    }

    // 全部成功：记录期望状态（重启对账基准）
    sqlx::query(
        "INSERT INTO desired_state (host_id, kind, state, applied_job_id, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) \
         ON CONFLICT(host_id, kind) DO UPDATE SET state=excluded.state, applied_job_id=excluded.applied_job_id, updated_at=CURRENT_TIMESTAMP"
    )
    .bind(job.host_id)
    .bind(&job.kind)
    .bind(&job.payload)
    .bind(job_id)
    .execute(&state.db)
    .await?;

    set_job_status(&state.db, job_id, "succeeded", None).await;
    let _ = crate::db::update_host_status(&state.db, job.host_id, "online").await;
    // 组件状态回写（netguard/arpfilter/optimize 安装与卸载）；回写失败在任务上标注
    if let Err(e) = crate::tasks::post_job_hook(state, &job).await {
        tracing::error!("Job {} 组件回写失败: {}", job_id, e);
        let _ = sqlx::query("UPDATE jobs SET error=? WHERE id=?")
            .bind(format!("任务成功但组件状态回写失败: {}", e))
            .bind(job_id)
            .execute(&state.db)
            .await;
    }
    Ok(())
}

/// 步骤失败处理：fail_closed 回滚已完成步骤；fail_open 保持现状（不断网优先）
/// 注意：传入的 steps 是执行前的快照，状态已过期；回滚前必须重查数据库
async fn handle_step_failure(
    state: &Arc<AppState>,
    job: &Job,
    signed: &SignedPayload,
    _steps_stale: &[JobStep],
    failed_step: &JobStep,
    err: &str,
) -> anyhow::Result<()> {
    if signed.failure_policy == POLICY_FAIL_CLOSED {
        // 重查步骤实时状态（内存快照里全部是 pending，直接用它回滚会漏掉已完成步骤）
        let steps = sqlx::query_as::<_, JobStep>("SELECT * FROM job_steps WHERE job_id = ? ORDER BY seq")
            .bind(job.id)
            .fetch_all(&state.db)
            .await?;
        let mut rollback_failed = false;
        let mut rollback_done = false;
        // 失败步骤自身可能已部分生效，先执行其 rollback_command
        if failed_step.rollback_command.is_some() {
            rollback_done = true;
            rollback_failed |= run_rollback_cmd(state, job, signed.timeout_secs, failed_step, true).await;
        }
        // 再逆序回滚之前已完成的步骤
        for step in steps.iter().rev() {
            if step.seq >= failed_step.seq || step.status != "succeeded" {
                continue;
            }
            if step.rollback_command.is_none() {
                continue;
            }
            rollback_done = true;
            rollback_failed |= run_rollback_cmd(state, job, signed.timeout_secs, step, false).await;
        }
        if rollback_failed {
            // 存在回滚失败：标记 failed，需人工介入，不得声称已回滚
            set_job_status(&state.db, job.id, "failed", Some(&format!(
                "步骤「{}」失败: {}；且部分回滚未成功，节点状态未知，需人工检查", failed_step.name, err
            ))).await;
        } else if !rollback_done {
            // 没有任何补偿命令可执行：不能宣称已回滚
            set_job_status(&state.db, job.id, "failed", Some(&format!(
                "步骤「{}」失败: {}；未声明回滚命令，节点可能残留部分变更，需人工检查", failed_step.name, err
            ))).await;
        } else {
            set_job_status(&state.db, job.id, "rolled_back", Some(&format!("步骤「{}」失败，已回滚: {}", failed_step.name, err))).await;
        }
    } else {
        // fail_open：不执行回滚动作，保持节点网络开放，任务标记 degraded 失败
        set_job_status(&state.db, job.id, "failed", Some(&format!("fail-open: 步骤「{}」失败，节点保持开放状态: {}", failed_step.name, err))).await;
    }
    Ok(())
}

/// 执行单步的回滚命令，返回是否失败（无回滚命令视为成功跳过）
/// is_failed_step=true 时回滚对象是本失败步骤（可能部分生效）
async fn run_rollback_cmd(state: &Arc<AppState>, job: &Job, timeout_secs: i64, step: &JobStep, is_failed_step: bool) -> bool {
    let Some(cmd) = &step.rollback_command else { return false };
    let host = match crate::db::get_host(&state.db, job.host_id).await {
        Ok(h) => h,
        Err(_) => return true,
    };
    let auth = match crate::deploy::SshAuth::from_host(
        host.password_encrypted.as_deref(),
        host.ssh_key_encrypted.as_deref(),
        &state.master_key,
    ) {
        Ok(a) => a,
        Err(_) => return true, // 凭据解密失败 → 回滚视为失败，需人工介入
    };
    let kh = Some(state.known_hosts_path.as_str());
    let exec = crate::deploy::ssh_exec_kh(&host.host, host.port as u16, &host.username, &auth, cmd, kh);
    match tokio::time::timeout(tokio::time::Duration::from_secs(timeout_secs as u64), exec).await {
        Ok(Ok(out)) => {
            let status = if is_failed_step { "failed" } else { "rolled_back" };
            finish_step(&state.db, step.id, status, Some(&format!("[回滚输出] {}", out)), Some(0)).await;
            false
        }
        Ok(Err(e)) => {
            finish_step(&state.db, step.id, "rollback_failed", Some(&e.to_string()), None).await;
            true
        }
        Err(_) => {
            finish_step(&state.db, step.id, "rollback_failed", Some("回滚超时"), None).await;
            true
        }
    }
}

/// 重跑失败任务：从检查点续跑；不可安全重跑且未回滚的任务拒绝重跑
pub async fn retry_job(state: &Arc<AppState>, job_id: i64, actor: &str) -> anyhow::Result<()> {
    let job = sqlx::query_as::<_, Job>("SELECT * FROM jobs WHERE id = ?")
        .bind(job_id)
        .fetch_one(&state.db)
        .await?;

    match job.status.as_str() {
        "failed" | "abandoned" | "rolled_back" => {}
        s => return Err(anyhow::anyhow!("当前状态 {} 不可重跑", s)),
    }

    let steps = sqlx::query_as::<_, JobStep>("SELECT * FROM job_steps WHERE job_id = ? ORDER BY seq")
        .bind(job_id)
        .fetch_all(&state.db)
        .await?;

    if job.status == "failed" {
        // 失败或中断（重启打断、结果未知）的步骤：声明为不可安全重跑的须先回滚或人工处理
        if let Some(fs) = steps.iter().find(|s| s.status == "failed" || s.status == "interrupted") {
            if !fs.rerun_safe {
                return Err(anyhow::anyhow!(
                    "步骤「{}」声明为不可安全重跑，且任务未完成回滚；请人工处理后新建任务", fs.name
                ));
            }
        }
    }

    // 重置失败/回滚/中断状态为 pending，保留 succeeded 步骤作为检查点
    sqlx::query("UPDATE job_steps SET status='pending', output=NULL, exit_code=NULL WHERE job_id=? AND status IN ('failed','rolled_back','rollback_failed','interrupted')")
        .bind(job_id)
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE jobs SET status='queued', error=NULL, started_at=NULL, finished_at=NULL, created_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(job_id)
        .execute(&state.db)
        .await?;

    crate::audit::log(
        &state.db, actor, "job.retry", Some("host"), Some(job.host_id),
        Some(&format!("job_id={}", job_id)), None,
    ).await;

    let state2 = state.clone();
    tokio::spawn(async move {
        run_locked(state2, job_id).await;
    });
    Ok(())
}

/// 平台重启对账：running 任务标记失败，其 running 步骤标记 interrupted（结果未知）；
/// 返回可重新入队的 queued 任务
pub async fn reconcile_on_boot(pool: &SqlitePool) -> anyhow::Result<Vec<i64>> {
    sqlx::query(
        "UPDATE job_steps SET status='interrupted', finished_at=CURRENT_TIMESTAMP \
         WHERE status='running' AND job_id IN (SELECT id FROM jobs WHERE status='running')"
    )
    .execute(pool)
    .await?;
    sqlx::query("UPDATE jobs SET status='failed', error='平台重启导致中断，可重跑', finished_at=CURRENT_TIMESTAMP WHERE status='running'")
        .execute(pool)
        .await?;
    let queued: Vec<(i64,)> = sqlx::query_as("SELECT id FROM jobs WHERE status='queued' ORDER BY id")
        .fetch_all(pool)
        .await?;
    Ok(queued.into_iter().map(|r| r.0).collect())
}

/// 重启后重新入队执行（run_locked 内含主机锁、TTL 与签名校验）
pub fn resume_background(state: Arc<AppState>, job_id: i64) {
    tokio::spawn(async move {
        run_locked(state, job_id).await;
    });
}

// ---- 状态更新助手 ----

async fn set_job_status(pool: &SqlitePool, id: i64, status: &str, error: Option<&str>) {
    let _ = sqlx::query("UPDATE jobs SET status=?, error=?, finished_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(status).bind(error).bind(id).execute(pool).await;
}

async fn set_job_running(pool: &SqlitePool, id: i64) {
    let _ = sqlx::query("UPDATE jobs SET status='running', started_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(id).execute(pool).await;
}

async fn set_step_running(pool: &SqlitePool, id: i64) {
    let _ = sqlx::query("UPDATE job_steps SET status='running', started_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(id).execute(pool).await;
}

async fn finish_step(pool: &SqlitePool, id: i64, status: &str, output: Option<&str>, exit_code: Option<i64>) {
    let truncated = output.map(|o| {
        if o.len() > MAX_OUTPUT_BYTES {
            // 按 UTF-8 字符边界截断，避免 panic
            let mut end = MAX_OUTPUT_BYTES;
            while !o.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...[截断]", &o[..end])
        } else {
            o.to_string()
        }
    });
    let _ = sqlx::query("UPDATE job_steps SET status=?, output=?, exit_code=?, finished_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(status).bind(truncated).bind(exit_code).bind(id).execute(pool).await;
}

/// 查询任务（含步骤）
pub async fn get_job_with_steps(pool: &SqlitePool, job_id: i64) -> anyhow::Result<(Job, Vec<JobStep>)> {
    let job = sqlx::query_as::<_, Job>("SELECT * FROM jobs WHERE id = ?")
        .bind(job_id)
        .fetch_one(pool)
        .await?;
    let steps = sqlx::query_as::<_, JobStep>("SELECT * FROM job_steps WHERE job_id = ? ORDER BY seq")
        .bind(job_id)
        .fetch_all(pool)
        .await?;
    Ok((job, steps))
}

pub async fn list_jobs(pool: &SqlitePool, host_id: Option<i64>, status: Option<&str>, limit: i64, offset: i64) -> anyhow::Result<Vec<Job>> {
    let mut sql = String::from("SELECT * FROM jobs WHERE 1=1");
    if host_id.is_some() {
        sql.push_str(" AND host_id = ?");
    }
    if let Some(s) = status {
        if !s.is_empty() {
            sql.push_str(" AND status = ?");
        }
    }
    sql.push_str(" ORDER BY id DESC LIMIT ? OFFSET ?");

    let mut q = sqlx::query_as::<_, Job>(&sql);
    if let Some(h) = host_id {
        q = q.bind(h);
    }
    if let Some(s) = status {
        if !s.is_empty() {
            q = q.bind(s.to_string());
        }
    }
    Ok(q.bind(limit).bind(offset).fetch_all(pool).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> JobSpec {
        JobSpec {
            kind: "netguard".into(),
            failure_policy: POLICY_FAIL_CLOSED.into(),
            timeout_secs: 300,
            queue_ttl_secs: 1800,
            steps: vec![StepSpec {
                name: "apply".into(),
                command: "true".into(),
                rollback_command: Some("false".into()),
                rerun_safe: true,
            }],
        }
    }

    #[test]
    fn signature_roundtrip_and_tamper_detect() {
        let key = signing_key(b"test-master-key-32-bytes-padding!!!");
        let payload = canonical_payload(1, 1, &spec());
        let sig = crate::crypto::hmac_sha256_hex(&key, payload.as_bytes());
        assert!(crate::crypto::hmac_sha256_verify(&key, payload.as_bytes(), &sig));
        // 篡改 payload 或签名均不通过
        assert!(!crate::crypto::hmac_sha256_verify(&key, b"tampered", &sig));
        assert!(!crate::crypto::hmac_sha256_verify(&key, payload.as_bytes(), &sig.replace('a', "b")));
        // seq 变化（跨任务重放）导致 payload 变化，签名失效
        let other = canonical_payload(1, 2, &spec());
        assert!(!crate::crypto::hmac_sha256_verify(&key, other.as_bytes(), &sig));
    }

    #[test]
    fn spec_validation() {
        assert!(validate_spec(&spec()).is_ok());
        let mut bad = spec();
        bad.failure_policy = "whatever".into();
        assert!(validate_spec(&bad).is_err());
        let mut empty = spec();
        empty.steps = vec![];
        assert!(validate_spec(&empty).is_err());
    }
}
