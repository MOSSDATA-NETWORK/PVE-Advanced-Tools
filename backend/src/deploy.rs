/// 自动部署检测脚本到 PVE 宿主机
/// 支持密码和 SSH 私钥认证
use tokio::process::Command;

const SCRIPT_CONTENT: &str = include_str!("../scripts/chicken-check.sh");

/// SSH 认证方式
pub enum SshAuth {
    Password(String),
    KeyContent(String),
    None,
}

impl SshAuth {
    /// 从 Host 信息构建认证方式。解密失败必须报错（失败关闭），
    /// 不得静默降级为 None——否则可能误用平台进程的默认 SSH 密钥/agent
    pub fn from_host(password_enc: Option<&str>, key_enc: Option<&str>, master_key: &[u8]) -> anyhow::Result<Self> {
        // 优先用私钥
        if let Some(enc) = key_enc {
            return Ok(SshAuth::KeyContent(
                crate::crypto::decrypt(enc, master_key)
                    .map_err(|e| anyhow::anyhow!("SSH 私钥解密失败: {}", e))?,
            ));
        }
        if let Some(enc) = password_enc {
            return Ok(SshAuth::Password(
                crate::crypto::decrypt(enc, master_key)
                    .map_err(|e| anyhow::anyhow!("SSH 密码解密失败: {}", e))?,
            ));
        }
        Ok(SshAuth::None)
    }
}

/// 临时文件守卫：作用域结束自动删除（覆盖错误路径不清理的问题）
struct TempFileGuard(String);

impl TempFileGuard {
    /// 以 O_EXCL + 0600 创建（无泄露窗口），写失败自动清理
    async fn write(content: &str, prefix: &str) -> anyhow::Result<Self> {
        let path = format!("/tmp/{}-{}", prefix, uuid::Uuid::new_v4());
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).await?;
        let guard = Self(path);
        tokio::io::AsyncWriteExt::write_all(&mut f, content.as_bytes()).await?;
        Ok(guard)
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// 验证主机名/用户名格式（防止命令注入）
pub fn validate_ssh_target(s: &str) -> anyhow::Result<()> {
    if s.is_empty() || s.len() > 253 {
        return Err(anyhow::anyhow!("主机名长度无效"));
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '@') {
        return Err(anyhow::anyhow!("主机名包含非法字符"));
    }
    Ok(())
}

/// 校验 VMID（纯数字，防止拼入远程命令时注入）
pub fn validate_vmid(vmid: &str) -> anyhow::Result<()> {
    if vmid.is_empty() || vmid.len() > 10 || !vmid.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow::anyhow!("VMID 必须为纯数字"));
    }
    Ok(())
}

/// 主机密钥校验参数：传入 known_hosts 文件路径即启用指纹固定（StrictHostKeyChecking=yes）
fn host_key_args(known_hosts: Option<&str>) -> Vec<String> {
    match known_hosts {
        Some(kh) => vec![
            "-o".to_string(), "StrictHostKeyChecking=yes".to_string(),
            "-o".to_string(), format!("UserKnownHostsFile={}", kh),
        ],
        None => vec![
            "-o".to_string(), "StrictHostKeyChecking=accept-new".to_string(),
        ],
    }
}

/// 主机已确认指纹时返回 known_hosts 路径，否则 None（宽松模式，仅限指纹确认前的引导连接）
pub fn host_known_hosts<'a>(known_hosts_path: &'a str, host: &crate::db::Host) -> Option<&'a str> {
    match host.host_key_status.as_deref() {
        Some("confirmed") => Some(known_hosts_path),
        _ => None,
    }
}

/// SSH 执行结果判定
fn check_output(output: &std::process::Output, strict: bool) -> anyhow::Result<String> {
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if strict {
        // 严格模式（任务框架）：非零退出即失败，避免「失败但有输出」被误判成功
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail: String = if stderr.trim().is_empty() {
                stdout.trim().chars().take(500).collect()
            } else {
                stderr.trim().chars().take(500).collect()
            };
            return Err(anyhow::anyhow!("命令退出码 {:?}: {}", output.status.code(), detail));
        }
        return Ok(stdout);
    }
    // 兼容模式（检测脚本）：历史行为——非零退出但 stdout 非空时仍返回输出
    if !output.status.success() && output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("SSH 执行失败: {}", stderr.trim()));
    }
    Ok(stdout)
}

/// SSH 命令执行（兼容模式，供检测脚本等历史路径使用）
pub async fn ssh_exec(host: &str, port: u16, user: &str, auth: &SshAuth, cmd: &str) -> anyhow::Result<String> {
    ssh_exec_impl(host, port, user, auth, cmd, None, false).await
}

/// SSH 命令执行（指纹固定 + 兼容判定）：检测路径升级指纹校验用
pub async fn ssh_exec_kh_tolerant(host: &str, port: u16, user: &str, auth: &SshAuth, cmd: &str, known_hosts: Option<&str>) -> anyhow::Result<String> {
    ssh_exec_impl(host, port, user, auth, cmd, known_hosts, false).await
}

/// SSH 命令执行（指纹固定 + 严格判定）：任务框架用，非零退出一律报错
pub async fn ssh_exec_kh(host: &str, port: u16, user: &str, auth: &SshAuth, cmd: &str, known_hosts: Option<&str>) -> anyhow::Result<String> {
    ssh_exec_impl(host, port, user, auth, cmd, known_hosts, true).await
}

async fn ssh_exec_impl(host: &str, port: u16, user: &str, auth: &SshAuth, cmd: &str, known_hosts: Option<&str>, strict: bool) -> anyhow::Result<String> {
    validate_ssh_target(host)?;
    validate_ssh_target(user)?;

    let mut args = host_key_args(known_hosts);
    args.extend([
        "-o".to_string(), "ConnectTimeout=10".to_string(),
        "-o".to_string(), "ServerAliveInterval=15".to_string(),
        "-o".to_string(), "ServerAliveCountMax=4".to_string(),
        "-p".to_string(), port.to_string(),
    ]);

    match auth {
        SshAuth::Password(pass) => {
            // 密码模式：不用 BatchMode（会禁用密码认证）
            // 写密码到临时文件，避免进程列表泄露
            let pass_guard = TempFileGuard::write(pass, "ssh-pass").await?;

            args.push("-i".to_string());
            args.push("/dev/null".to_string()); // 不用密钥文件
            args.push(format!("{}@{}", user, host));
            args.push(cmd.to_string());

            let output = Command::new("sshpass")
                .args(["-f", &pass_guard.0])
                .arg("ssh")
                .args(&args)
                .kill_on_drop(true)
                .output()
                .await
                .map_err(|_| anyhow::anyhow!("sshpass 未安装"))?;

            return check_output(&output, strict);
        }
        SshAuth::KeyContent(key) => {
            // 密钥模式：可以用 BatchMode
            args.push("-o".to_string());
            args.push("BatchMode=yes".to_string());
            let key_guard = TempFileGuard::write(key, "ssh-key").await?;
            args.push("-i".to_string());
            args.push(key_guard.0.clone());
        }
        SshAuth::None => {
            args.push("-o".to_string());
            args.push("BatchMode=yes".to_string());
        }
    }

    args.push(format!("{}@{}", user, host));
    args.push(cmd.to_string());

    let output = Command::new("ssh")
        .args(&args)
        .kill_on_drop(true)
        .output()
        .await?;

    check_output(&output, strict)
}

/// SCP 上传文件
async fn scp_upload(host: &str, port: u16, user: &str, auth: &SshAuth, local_path: &str, remote_path: &str, known_hosts: Option<&str>) -> anyhow::Result<()> {
    validate_ssh_target(host)?;
    validate_ssh_target(user)?;

    let mut base_args = host_key_args(known_hosts);
    base_args.extend([
        "-P".to_string(), port.to_string(),
    ]);

    match auth {
        SshAuth::Password(pass) => {
            let pass_guard = TempFileGuard::write(pass, "ssh-pass").await?;

            let output = Command::new("sshpass")
                .args(["-f", &pass_guard.0, "scp"])
                .args(&base_args)
                .args([local_path, &format!("{}@{}:{}", user, host, remote_path)])
                .kill_on_drop(true)
                .output()
                .await
                .map_err(|_| anyhow::anyhow!("sshpass 未安装"))?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("SCP 失败: {}", String::from_utf8_lossy(&output.stderr)));
            }
            return Ok(());
        }
        SshAuth::KeyContent(key) => {
            let key_guard = TempFileGuard::write(key, "ssh-key").await?;
            base_args.push("-i".to_string());
            base_args.push(key_guard.0.clone());
        }
        SshAuth::None => {}
    }

    let output = Command::new("scp")
        .args(&base_args)
        .args([local_path, &format!("{}@{}:{}", user, host, remote_path)])
        .kill_on_drop(true)
        .output()
        .await?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("SCP 失败: {}", String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

/// 部署检测脚本到 PVE 主机（可选指纹固定）
pub async fn deploy_script_kh(host: &str, port: u16, user: &str, auth: &SshAuth, known_hosts: Option<&str>) -> anyhow::Result<()> {
    // 写临时脚本文件
    let tmp_path = format!("/tmp/chicken-check-{}.sh", uuid::Uuid::new_v4());
    tokio::fs::write(&tmp_path, SCRIPT_CONTENT).await?;

    // 上传
    let remote_path = "/usr/local/bin/chicken-check";
    let r = scp_upload(host, port, user, auth, &tmp_path, remote_path, known_hosts).await;
    let _ = tokio::fs::remove_file(&tmp_path).await;
    r?;

    // 设置执行权限
    ssh_exec_kh(host, port, user, auth, &format!("chmod +x {}", remote_path), known_hosts).await?;

    // 验证安装
    let result = ssh_exec_kh(host, port, user, auth, "chicken-check --check-agent", known_hosts).await?;
    if result.contains("\"agent\":\"installed\"") {
        tracing::info!("检测脚本已部署到 {}@{}", user, host);
    } else {
        return Err(anyhow::anyhow!("脚本部署验证失败"));
    }

    Ok(())
}

/// 远程执行检测（可选指纹固定）
pub async fn run_remote_scan(host: &str, port: u16, user: &str, auth: &SshAuth, vmid: Option<&str>, known_hosts: Option<&str>) -> anyhow::Result<String> {
    let cmd = match vmid {
        // 单台扫描由「磁盘扫描」按钮触发，强制磁盘挂载模式（GA被禁/无GA都能查）
        Some(id) => {
            validate_vmid(id)?;
            format!("chicken-check --vmid {} --disk", id)
        }
        None => "chicken-check --all".to_string(),
    };
    let result = ssh_exec_kh_tolerant(host, port, user, auth, &cmd, known_hosts).await?;
    Ok(result)
}

/// 检查远程脚本版本（可选指纹固定）
pub async fn check_script_version_kh(host: &str, port: u16, user: &str, auth: &SshAuth, known_hosts: Option<&str>) -> Option<String> {
    let result = ssh_exec_kh_tolerant(host, port, user, auth, "chicken-check --version 2>/dev/null || echo none", known_hosts).await.ok()?;
    let v = result.trim().to_string();
    if v == "none" || v.is_empty() { None } else { Some(v) }
}

/// 批量重新部署脚本到所有已部署的主机
pub async fn redeploy_all(pool: &sqlx::SqlitePool, master_key: &[u8], known_hosts_path: &str) -> anyhow::Result<()> {
    let hosts = crate::db::list_hosts(pool).await?;
    let current_version = crate::version::SCRIPT_VERSION;
    let mut deployed = 0;
    let mut skipped = 0;
    let mut failed = 0;

    for host in &hosts {
        if !host.agent_deployed {
            skipped += 1;
            continue;
        }

        let auth = match SshAuth::from_host(
            host.password_encrypted.as_deref(),
            host.ssh_key_encrypted.as_deref(),
            master_key,
        ) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("Redeploy {} skipped: {}", host.name, e);
                failed += 1;
                continue;
            }
        };
        let kh = host_known_hosts(known_hosts_path, host);

        // 检查远程脚本版本
        let remote_version = check_script_version_kh(&host.host, host.port as u16, &host.username, &auth, kh).await;

        if remote_version.as_deref() == Some(current_version) {
            skipped += 1;
            continue;
        }

        // 版本不同或无版本，重新部署
        tracing::info!("Redeploying script to {} (remote={}, target={})", host.name, remote_version.unwrap_or_default(), current_version);
        match deploy_script_kh(&host.host, host.port as u16, &host.username, &auth, kh).await {
            Ok(_) => {
                deployed += 1;
                let _ = crate::db::update_host_agent_status(pool, host.id, true).await;
            }
            Err(e) => {
                tracing::warn!("Redeploy to {} failed: {}", host.name, e);
                failed += 1;
            }
        }
    }

    tracing::info!("Script redeploy: {} deployed, {} skipped, {} failed", deployed, skipped, failed);
    Ok(())
}
