use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Host {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: i64,
    pub username: String,
    pub auth_type: String,
    pub password_encrypted: Option<String>,
    pub ssh_key_encrypted: Option<String>,
    pub api_token_encrypted: Option<String>,
    pub status: String,
    pub agent_deployed: bool,
    pub last_check: Option<NaiveDateTime>,
    pub host_key_fingerprint: Option<String>,
    pub host_key_known_hosts: Option<String>,
    pub host_key_status: Option<String>,
    pub pve_version: Option<String>,
    pub capabilities: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize)]
pub struct HostPublic {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: i64,
    pub username: String,
    pub auth_type: String,
    pub has_password: bool,
    pub has_ssh_key: bool,
    pub has_api_token: bool,
    pub status: String,
    pub agent_deployed: bool,
    pub last_check: Option<NaiveDateTime>,
    pub host_key_fingerprint: Option<String>,
    pub host_key_status: Option<String>,
    pub pve_version: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl Host {
    pub fn to_public(&self) -> HostPublic {
        HostPublic {
            id: self.id,
            name: self.name.clone(),
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            auth_type: self.auth_type.clone(),
            has_password: self.password_encrypted.is_some(),
            has_ssh_key: self.ssh_key_encrypted.is_some(),
            has_api_token: self.api_token_encrypted.is_some(),
            status: self.status.clone(),
            agent_deployed: self.agent_deployed,
            last_check: self.last_check,
            host_key_fingerprint: self.host_key_fingerprint.clone(),
            host_key_status: self.host_key_status.clone(),
            pve_version: self.pve_version.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateHost {
    pub name: String,
    pub host: String,
    /// 所属集群（QoS 快照 clusters 成员；缺省 1=默认集群）
    pub cluster_id: Option<i64>,
    pub port: Option<i64>,
    pub username: Option<String>,
    pub auth_type: Option<String>,
    pub password: Option<String>,
    pub ssh_key_content: Option<String>,
    pub api_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateHost {
    pub name: Option<String>,
    pub host: Option<String>,
    pub cluster_id: Option<i64>,
    pub port: Option<i64>,
    pub username: Option<String>,
    pub auth_type: Option<String>,
    pub password: Option<String>,
    pub ssh_key_content: Option<String>,
    pub api_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Scan {
    pub id: i64,
    pub host_id: Option<i64>,
    pub status: String,
    pub total_vms: i64,
    pub ga_count: i64,
    pub disk_count: i64,
    pub found_count: i64,
    pub started_at: Option<NaiveDateTime>,
    pub completed_at: Option<NaiveDateTime>,
    pub error: Option<String>,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Result {
    pub id: i64,
    pub scan_id: Option<i64>,
    pub host_id: Option<i64>,
    pub vmid: String,
    pub status: String,
    pub method: Option<String>,
    pub evidence: Option<String>,
    pub first_seen: Option<NaiveDateTime>,
    pub last_seen: Option<NaiveDateTime>,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Notification {
    pub id: i64,
    #[serde(rename = "type")]
    pub r#type: String,
    pub enabled: bool,
    pub config_encrypted: String,
    pub notify_level: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize)]
pub struct NotificationPublic {
    pub id: i64,
    #[serde(rename = "type")]
    pub r#type: String,
    pub enabled: bool,
    pub config: String,
    pub notify_level: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct CreateNotification {
    pub r#type: String,
    pub enabled: Option<bool>,
    pub config: String,
    pub notify_level: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Schedule {
    pub id: i64,
    pub host_id: Option<i64>,
    pub cron_expr: String,
    pub enabled: bool,
    pub last_run: Option<NaiveDateTime>,
    pub next_run: Option<NaiveDateTime>,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSchedule {
    pub host_id: Option<i64>,
    pub cron_expr: String,
    pub enabled: Option<bool>,
}

// ---- Host CRUD ----

pub async fn list_hosts(pool: &SqlitePool) -> anyhow::Result<Vec<Host>> {
    Ok(sqlx::query_as::<_, Host>("SELECT * FROM hosts ORDER BY id DESC").fetch_all(pool).await?)
}

pub async fn get_host(pool: &SqlitePool, id: i64) -> anyhow::Result<Host> {
    Ok(sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE id = ?").bind(id).fetch_one(pool).await?)
}

pub async fn create_host(pool: &SqlitePool, h: CreateHost, master_key: &[u8]) -> anyhow::Result<Host> {
    let port = h.port.unwrap_or(22);
    let username = h.username.unwrap_or_else(|| "root".to_string());
    let auth_type = h.auth_type.unwrap_or_else(|| "password".to_string());
    let password_enc = h.password.map(|p| crate::crypto::encrypt(&p, master_key));
    let key_enc = h.ssh_key_content.map(|k| crate::crypto::encrypt(&k, master_key));
    let token_enc = h.api_token.map(|t| crate::crypto::encrypt(&t, master_key));

    let id = sqlx::query(
        "INSERT INTO hosts (name, host, port, username, auth_type, password_encrypted, ssh_key_encrypted, api_token_encrypted, cluster_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&h.name).bind(&h.host).bind(port).bind(&username).bind(&auth_type).bind(&password_enc).bind(&key_enc).bind(&token_enc).bind(h.cluster_id.unwrap_or(1))
    .execute(pool).await?.last_insert_rowid();
    get_host(pool, id).await
}

pub async fn update_host(pool: &SqlitePool, id: i64, h: UpdateHost, master_key: &[u8]) -> anyhow::Result<Host> {
    let existing = get_host(pool, id).await?;
    let name = h.name.unwrap_or(existing.name);
    let host = h.host.unwrap_or(existing.host);
    let port = h.port.unwrap_or(existing.port);
    let username = h.username.unwrap_or(existing.username);
    let auth_type = h.auth_type.unwrap_or(existing.auth_type);

    let password_enc = match h.password {
        Some(p) if !p.is_empty() => Some(crate::crypto::encrypt(&p, master_key)),
        _ => existing.password_encrypted,
    };
    let key_enc = match h.ssh_key_content {
        Some(k) if !k.is_empty() => Some(crate::crypto::encrypt(&k, master_key)),
        _ => existing.ssh_key_encrypted,
    };
    let token_enc = match h.api_token {
        Some(t) if !t.is_empty() => Some(crate::crypto::encrypt(&t, master_key)),
        _ => existing.api_token_encrypted,
    };

    sqlx::query("UPDATE hosts SET name=?, host=?, port=?, username=?, auth_type=?, password_encrypted=?, ssh_key_encrypted=?, api_token_encrypted=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(&name).bind(&host).bind(port).bind(&username).bind(&auth_type).bind(&password_enc).bind(&key_enc).bind(&token_enc).bind(id)
        .execute(pool).await?;
    get_host(pool, id).await
}

pub async fn delete_host(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM hosts WHERE id = ?").bind(id).execute(pool).await?;
    Ok(())
}

pub async fn update_host_status(pool: &SqlitePool, id: i64, status: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE hosts SET status=?, last_check=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(status).bind(id).execute(pool).await?;
    Ok(())
}

pub async fn update_host_agent_status(pool: &SqlitePool, id: i64, deployed: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE hosts SET agent_deployed=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(deployed).bind(id).execute(pool).await?;
    Ok(())
}

// ---- Scan CRUD ----

pub async fn list_scans(pool: &SqlitePool, limit: i64, offset: i64) -> anyhow::Result<Vec<Scan>> {
    Ok(sqlx::query_as::<_, Scan>("SELECT * FROM scans ORDER BY id DESC LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?)
}

pub async fn count_scans(pool: &SqlitePool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM scans")
        .fetch_one(pool)
        .await?)
}

pub async fn create_scan(pool: &SqlitePool, host_id: Option<i64>) -> anyhow::Result<Scan> {
    let id = sqlx::query("INSERT INTO scans (host_id, status) VALUES (?, 'pending')")
        .bind(host_id).execute(pool).await?.last_insert_rowid();
    Ok(sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = ?").bind(id).fetch_one(pool).await?)
}

/// 更新扫描状态，running 时自动设置 started_at
pub async fn update_scan_status(pool: &SqlitePool, id: i64, status: &str) -> anyhow::Result<()> {
    if status == "running" {
        sqlx::query("UPDATE scans SET status=?, started_at=CURRENT_TIMESTAMP WHERE id=?")
            .bind(status).bind(id).execute(pool).await?;
    } else {
        sqlx::query("UPDATE scans SET status=? WHERE id=?")
            .bind(status).bind(id).execute(pool).await?;
    }
    Ok(())
}

pub async fn complete_scan(pool: &SqlitePool, id: i64, total: i64, ga: i64, disk: i64, found: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE scans SET status='completed', total_vms=?, ga_count=?, disk_count=?, found_count=?, completed_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(total).bind(ga).bind(disk).bind(found).bind(id).execute(pool).await?;
    Ok(())
}

pub async fn fail_scan(pool: &SqlitePool, id: i64, error: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE scans SET status='failed', error=?, completed_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(error).bind(id).execute(pool).await?;
    Ok(())
}

pub async fn update_scan_progress(pool: &SqlitePool, id: i64, total: i64, ga: i64, disk: i64, found: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE scans SET total_vms=?, ga_count=?, disk_count=?, found_count=? WHERE id=?")
        .bind(total).bind(ga).bind(disk).bind(found).bind(id).execute(pool).await?;
    Ok(())
}

// ---- Result CRUD ----

pub async fn list_results(pool: &SqlitePool, host_id: Option<i64>, status: Option<&str>, limit: i64, offset: i64) -> anyhow::Result<Vec<crate::db::Result>> {
    let mut sql = String::from("SELECT * FROM results WHERE 1=1");
    let mut binds: Vec<String> = vec![];

    if let Some(hid) = host_id {
        binds.push(hid.to_string());
        sql.push_str(&format!(" AND host_id = ${}", binds.len()));
    }
    if let Some(s) = status {
        if !s.is_empty() {
            binds.push(s.to_string());
            sql.push_str(&format!(" AND status = ${}", binds.len()));
        }
    }

    sql.push_str(" ORDER BY last_seen DESC");
    binds.push(limit.to_string());
    sql.push_str(&format!(" LIMIT ${}", binds.len()));
    binds.push(offset.to_string());
    sql.push_str(&format!(" OFFSET ${}", binds.len()));

    let mut query = sqlx::query_as::<_, crate::db::Result>(&sql);
    for b in &binds {
        query = query.bind(b);
    }
    Ok(query.fetch_all(pool).await?)
}

pub async fn count_results(pool: &SqlitePool, host_id: Option<i64>, status: Option<&str>) -> anyhow::Result<i64> {
    let mut sql = String::from("SELECT COUNT(*) FROM results WHERE 1=1");
    let mut binds: Vec<String> = vec![];

    if let Some(hid) = host_id {
        binds.push(hid.to_string());
        sql.push_str(&format!(" AND host_id = ${}", binds.len()));
    }
    if let Some(s) = status {
        if !s.is_empty() {
            binds.push(s.to_string());
            sql.push_str(&format!(" AND status = ${}", binds.len()));
        }
    }

    let mut query = sqlx::query_scalar(&sql);
    for b in &binds {
        query = query.bind(b);
    }
    Ok(query.fetch_one(pool).await?)
}

/// 检测结果 upsert：依赖 (host_id, vmid) 唯一索引原子执行，并发扫描不产生重复行。
/// scan_id <= 0 表示无关联扫描（如手动单台磁盘扫描），不写该列以免违反外键。
pub async fn upsert_result(pool: &SqlitePool, scan_id: i64, host_id: i64, vmid: &str, status: &str, method: &str, evidence: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO results (scan_id, host_id, vmid, status, method, evidence, first_seen, last_seen)          VALUES (NULLIF(?, 0), ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)          ON CONFLICT(host_id, vmid) DO UPDATE SET            status=excluded.status, method=excluded.method, evidence=excluded.evidence, last_seen=CURRENT_TIMESTAMP,            scan_id=CASE WHEN excluded.scan_id IS NOT NULL THEN excluded.scan_id ELSE results.scan_id END"
    )
    .bind(scan_id).bind(host_id).bind(vmid).bind(status).bind(method).bind(evidence)
    .execute(pool).await?;
    Ok(())
}

pub async fn get_previous_results(pool: &SqlitePool, host_id: i64) -> anyhow::Result<Vec<crate::db::Result>> {
    Ok(sqlx::query_as::<_, crate::db::Result>("SELECT * FROM results WHERE host_id = ? AND status != 'cleaned' ORDER BY id DESC")
        .bind(host_id).fetch_all(pool).await?)
}

// ---- Notification CRUD ----

pub async fn list_notifications(pool: &SqlitePool) -> anyhow::Result<Vec<Notification>> {
    Ok(sqlx::query_as::<_, Notification>("SELECT * FROM notifications ORDER BY id").fetch_all(pool).await?)
}

pub async fn upsert_notification(pool: &SqlitePool, id: Option<i64>, n: CreateNotification, master_key: &[u8]) -> anyhow::Result<Notification> {
    let enabled = n.enabled.unwrap_or(true);
    let level = n.notify_level.unwrap_or_else(|| "detected_and_cleaned".to_string());
    let encrypted = crate::crypto::encrypt(&n.config, master_key);

    match id {
        Some(id) => {
            sqlx::query("UPDATE notifications SET type=?, enabled=?, config_encrypted=?, notify_level=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
                .bind(&n.r#type).bind(enabled).bind(&encrypted).bind(&level).bind(id).execute(pool).await?;
            Ok(sqlx::query_as::<_, Notification>("SELECT * FROM notifications WHERE id=?").bind(id).fetch_one(pool).await?)
        }
        None => {
            let new_id = sqlx::query("INSERT INTO notifications (type, enabled, config_encrypted, notify_level) VALUES (?, ?, ?, ?)")
                .bind(&n.r#type).bind(enabled).bind(&encrypted).bind(&level).execute(pool).await?.last_insert_rowid();
            Ok(sqlx::query_as::<_, Notification>("SELECT * FROM notifications WHERE id=?").bind(new_id).fetch_one(pool).await?)
        }
    }
}

// ---- Schedule CRUD ----

pub async fn list_schedules(pool: &SqlitePool) -> anyhow::Result<Vec<Schedule>> {
    Ok(sqlx::query_as::<_, Schedule>("SELECT * FROM schedules ORDER BY id").fetch_all(pool).await?)
}

pub async fn create_schedule(pool: &SqlitePool, s: CreateSchedule) -> anyhow::Result<Schedule> {
    let enabled = s.enabled.unwrap_or(true);
    let id = sqlx::query("INSERT INTO schedules (host_id, cron_expr, enabled) VALUES (?, ?, ?)")
        .bind(s.host_id).bind(&s.cron_expr).bind(enabled).execute(pool).await?.last_insert_rowid();
    Ok(sqlx::query_as::<_, Schedule>("SELECT * FROM schedules WHERE id=?").bind(id).fetch_one(pool).await?)
}

pub async fn delete_schedule(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM schedules WHERE id=?").bind(id).execute(pool).await?;
    Ok(())
}
