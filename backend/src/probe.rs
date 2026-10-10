//! 主机能力探测（P0）：部署前探测 PVE 版本与架构差异，而非硬编码
//! 兼容矩阵：PVE 7.x / 8.x / 9.x
use serde::Serialize;
use std::sync::Arc;

use crate::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    /// PVE 主版本号（7/8/9），无法识别为 None
    pub pve_major: Option<u32>,
    pub arch: String,
    /// 该主版本是否在支持矩阵内
    pub supported: bool,
}

/// 探测主机能力并写库，返回解析结果
pub async fn probe_capabilities(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<Capabilities> {
    let host = crate::db::get_host(&state.db, host_id).await?;
    if host.host_key_status.as_deref() != Some("confirmed") {
        return Err(anyhow::anyhow!("主机密钥指纹未确认，拒绝连接"));
    }
    let auth = crate::deploy::SshAuth::from_host(
        host.password_encrypted.as_deref(),
        host.ssh_key_encrypted.as_deref(),
        &state.master_key,
    )?;
    let kh = Some(state.known_hosts_path.as_str());

    let out = crate::deploy::ssh_exec_kh(
        &host.host, host.port as u16, &host.username, &auth,
        "pveversion 2>/dev/null | head -1; uname -m",
        kh,
    ).await?;

    let mut lines = out.lines();
    let version_line = lines.next().unwrap_or("").trim().to_string();
    let arch = lines.next().unwrap_or("unknown").trim().to_string();

    // 形如 "pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.4-2-pve)"
    let pve_major = version_line
        .strip_prefix("pve-manager/")
        .and_then(|rest| rest.split('.').next())
        .and_then(|major| major.parse::<u32>().ok());

    let caps = Capabilities {
        pve_major,
        arch,
        supported: matches!(pve_major, Some(7) | Some(8) | Some(9)),
    };

    let pve_version = if version_line.is_empty() { None } else { Some(version_line) };
    sqlx::query("UPDATE hosts SET pve_version=?, capabilities=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(&pve_version)
        .bind(serde_json::to_string(&caps)?)
        .bind(host_id)
        .execute(&state.db)
        .await?;

    Ok(caps)
}
