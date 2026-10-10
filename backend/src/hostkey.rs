//! SSH 主机密钥指纹固定（TOFU）
//! 首次接入通过 ssh-keyscan 抓取指纹，用户在面板确认后写入平台维护的
//! known_hosts 文件；之后所有 SSH 连接使用 StrictHostKeyChecking=yes，防中间人。
use sqlx::SqlitePool;
use tokio::process::Command;

/// 抓取主机密钥，返回 (known_hosts 行, SHA256 指纹)
pub async fn scan(host: &str, port: u16) -> anyhow::Result<(String, String)> {
    crate::deploy::validate_ssh_target(host)?;

    let out = Command::new("ssh-keyscan")
        .args(["-T", "5", "-p", &port.to_string(), host])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("ssh-keyscan 执行失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    // 优先 ed25519，其次 rsa/ecdsa；跳过注释行
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .collect();
    if lines.is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!("未获取到主机密钥: {}", stderr.trim()));
    }
    let pick = |algo: &str| lines.iter().find(|l| l.contains(algo)).map(|s| s.to_string());
    let line = pick("ssh-ed25519")
        .or_else(|| pick("ecdsa-sha2"))
        .or_else(|| pick("ssh-rsa"))
        .unwrap_or_else(|| lines[0].to_string());

    // 用 ssh-keygen 计算指纹
    let tmp = format!("/tmp/hostkey-{}", uuid::Uuid::new_v4());
    tokio::fs::write(&tmp, &line).await?;
    let fp_out = Command::new("ssh-keygen")
        .args(["-lf", &tmp])
        .output()
        .await;
    let _ = tokio::fs::remove_file(&tmp).await;
    let fp_out = fp_out.map_err(|e| anyhow::anyhow!("ssh-keygen 执行失败: {}", e))?;
    let fp_stdout = String::from_utf8_lossy(&fp_out.stdout);
    // 输出形如: "256 SHA256:xxxx root@host (ED25519)"
    let fingerprint = fp_stdout
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("指纹解析失败: {}", fp_stdout.trim()))?
        .to_string();

    Ok((line, fingerprint))
}

/// 重写平台 known_hosts 文件（所有已确认主机的密钥行），返回条目数
pub async fn write_known_hosts(pool: &SqlitePool, path: &str) -> anyhow::Result<usize> {
    let rows: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT host_key_known_hosts FROM hosts WHERE host_key_status = 'confirmed' AND host_key_known_hosts IS NOT NULL"
    )
    .fetch_all(pool)
    .await?;

    let mut content = String::new();
    let mut count = 0;
    for (line,) in rows {
        if let Some(l) = line {
            let l = l.trim();
            if !l.is_empty() {
                content.push_str(l);
                content.push('\n');
                count += 1;
            }
        }
    }

    if let Some(parent) = std::path::Path::new(path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    // 唯一临时文件 + 原子替换，避免并发确认互相覆盖
    let tmp = format!("{}.tmp.{}", path, uuid::Uuid::new_v4());
    tokio::fs::write(&tmp, content).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await;
    }
    tokio::fs::rename(&tmp, path).await?;
    Ok(count)
}
