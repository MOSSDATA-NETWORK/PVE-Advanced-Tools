//! 版本管理模块
//! - 编译时嵌入版本号（语义化版本，自首个版本启用）
//! - GitHub API 检查新版本
//! - 一键更新：SHA256SUMS 校验 + 原子替换 + 更新前备份 SQLite 与旧二进制
//! - 更新标记：启动时校验，迁移失败可从 .bak 恢复（见 README 回滚说明）
use serde::{Deserialize, Serialize};

/// 当前版本（编译时从 Cargo.toml 读取）
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// 检测脚本版本（脚本内容变化时递增，用于触发自动重新部署）
pub const SCRIPT_VERSION: &str = "7";

/// 更新来源仓库：环境变量 UPDATE_GITHUB_REPO 可覆盖
pub fn github_repo() -> String {
    std::env::var("UPDATE_GITHUB_REPO")
        .unwrap_or_else(|_| "MOSSDATA-NETWORK/PVE-Advanced-Tools".to_string())
}

/// systemd 服务名：环境变量 SYSTEMD_SERVICE 可覆盖
fn systemd_service() -> String {
    std::env::var("SYSTEMD_SERVICE").unwrap_or_else(|_| "pve-advanced-tools".to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionInfo {
    pub current: String,
    pub latest: Option<String>,
    pub update_available: bool,
    pub release_url: Option<String>,
    pub release_notes: Option<String>,
    pub published_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    html_url: String,
    published_at: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    #[allow(dead_code)]
    size: u64,
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap_or_default()
}

/// 下载更新包用：程序约 20 MB，慢速线路上 60 秒总超时不够；连不上时仍尽快失败
fn download_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(15 * 60))
        .build()
        .unwrap_or_default()
}

fn user_agent() -> String {
    format!("PVE-Advanced-Tools/{}", VERSION)
}

/// 检查 GitHub 最新版本
pub async fn check_update() -> anyhow::Result<VersionInfo> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", github_repo());
    let client = http_client();

    let resp = client.get(&url)
        .header("User-Agent", user_agent())
        .send()
        .await?;

    // 查询失败必须报错：当作「无更新」会在界面上显示成「已是最新版本」
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!(match status.as_u16() {
            403 | 429 => "GitHub 接口访问次数超限，请稍后再试".to_string(),
            404 => "GitHub 上还没有已发布的版本".to_string(),
            _ => format!("无法从 GitHub 获取最新版本（HTTP {}）", status.as_u16()),
        }));
    }

    let release: GithubRelease = resp.json().await?;

    let latest_version = release.tag_name.trim_start_matches('v').to_string();
    let update_available = is_newer(&latest_version, VERSION);

    Ok(VersionInfo {
        current: VERSION.to_string(),
        latest: Some(latest_version),
        update_available,
        release_url: Some(release.html_url),
        release_notes: release.body,
        published_at: Some(release.published_at),
    })
}

/// 获取最近的更新日志（最近5个 release）
pub async fn get_changelog() -> anyhow::Result<Vec<ChangelogEntry>> {
    let url = format!("https://api.github.com/repos/{}/releases?per_page=5", github_repo());
    let client = http_client();

    let resp = client.get(&url)
        .header("User-Agent", user_agent())
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(vec![]);
    }

    let releases: Vec<GithubRelease> = resp.json().await?;

    Ok(releases.into_iter().map(|r| ChangelogEntry {
        version: r.tag_name.trim_start_matches('v').to_string(),
        name: r.name.unwrap_or_else(|| r.tag_name.clone()),
        notes: r.body.unwrap_or_default(),
        url: r.html_url,
        published_at: r.published_at,
    }).collect())
}

#[derive(Debug, Serialize)]
pub struct ChangelogEntry {
    pub version: String,
    pub name: String,
    pub notes: String,
    pub url: String,
    pub published_at: String,
}

/// 当前平台的二进制制品名
fn asset_name() -> anyhow::Result<String> {
    let name = if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "pve-advanced-tools-linux-x86_64"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "pve-advanced-tools-linux-aarch64"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "pve-advanced-tools-macos-aarch64"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "pve-advanced-tools-macos-x86_64"
    } else {
        return Err(anyhow::anyhow!("当前平台不支持自动更新"));
    };
    Ok(name.to_string())
}

/// 从 DATABASE_URL 解析 SQLite 文件路径（仅支持本地文件形式）
fn sqlite_file_path() -> Option<String> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:pve-advanced-tools.db?mode=rwc".to_string());
    let path = url.strip_prefix("sqlite:")?.split('?').next()?.to_string();
    if path.is_empty() || path == ":memory:" {
        return None;
    }
    Some(path)
}

/// 按 SHA256SUMS（sha256sum 输出格式）核对制品哈希；文件名须完全一致
fn check_sha256(sums_text: &str, asset_name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let expected = sums_text.lines()
        .find_map(|line| {
            let mut it = line.split_whitespace();
            let hash = it.next()?;
            let fname = it.next()?;
            if fname.trim_start_matches('*') == asset_name { Some(hash.to_string()) } else { None }
        })
        .ok_or_else(|| anyhow::anyhow!("SHA256SUMS 中未找到 {} 的哈希", asset_name))?;

    use sha2::Digest;
    let actual = format!("{:x}", sha2::Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(&expected) {
        return Err(anyhow::anyhow!("制品 SHA256 校验失败（期望 {}，实际 {}），已中止更新", expected, actual));
    }
    Ok(())
}

/// 下载制品，并按同一发布附带的 SHA256SUMS 校验哈希（不做签名校验）
async fn download_verified(client: &reqwest::Client, release: &GithubRelease, asset_name: &str) -> anyhow::Result<Vec<u8>> {
    let asset = release.assets.iter().find(|a| a.name == asset_name)
        .ok_or_else(|| anyhow::anyhow!("未找到适合当前平台的更新包: {}", asset_name))?;

    // SHA256SUMS 为强制校验项（沿用 vmqos 发布传统）：缺失即拒绝更新
    let sums_asset = release.assets.iter().find(|a| a.name == "SHA256SUMS")
        .ok_or_else(|| anyhow::anyhow!("发布缺少 SHA256SUMS 校验文件，拒绝更新"))?;

    let sums_text = client.get(&sums_asset.browser_download_url)
        .header("User-Agent", user_agent())
        .send().await?
        .error_for_status()?
        .text().await?;

    let bytes = client.get(&asset.browser_download_url)
        .header("User-Agent", user_agent())
        .send().await?
        .error_for_status()?
        .bytes().await?;

    check_sha256(&sums_text, asset_name, &bytes)?;
    tracing::info!("制品 SHA256 校验通过");
    Ok(bytes.to_vec())
}

/// 更新锁：同时只允许一个更新流程
static UPDATE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

/// 执行更新：校验哈希 → 一致性备份数据库与旧二进制 → 原子替换 → 延迟重启
pub async fn perform_update(pool: &sqlx::SqlitePool) -> anyhow::Result<String> {
    // 容器里替换的程序会在重建容器时丢失，且没有 systemd 可重启：在下载和改动任何文件之前拒绝
    if std::env::var("DEPLOY_MODE").as_deref() == Ok("docker") {
        return Err(anyhow::anyhow!("Docker 部署请用新版镜像更新：下载并 docker load 新镜像后重建容器（见 README 的 Docker 部署）"));
    }
    let lock = UPDATE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()));
    let Ok(_guard) = lock.try_lock() else {
        return Err(anyhow::anyhow!("已有更新流程在进行中"));
    };
    let url = format!("https://api.github.com/repos/{}/releases/latest", github_repo());
    let client = http_client();

    let resp = client.get(&url)
        .header("User-Agent", user_agent())
        .send()
        .await?
        .error_for_status()?;

    let release: GithubRelease = resp.json().await?;
    let asset_name = asset_name()?;
    let bytes = download_verified(&download_client(), &release, &asset_name).await?;

    let current_exe = std::env::current_exe()?;

    // 更新前备份 SQLite 数据库：VACUUM INTO 保证一致性（热拷贝可能遇到 WAL 中间态）
    // 先备份到临时文件，成功后原子替换旧备份——失败时旧 .bak 仍在
    if let Some(db_path) = sqlite_file_path() {
        let db_bak = format!("{}.bak", db_path);
        let db_bak_tmp = format!("{}.bak.tmp", db_path);
        let _ = tokio::fs::remove_file(&db_bak_tmp).await;
        let escaped = db_bak_tmp.replace('\'', "''");
        sqlx::query(&format!("VACUUM INTO '{}'", escaped))
            .execute(pool)
            .await
            .map_err(|e| anyhow::anyhow!("数据库备份失败（旧备份保留）: {}", e))?;
        tokio::fs::rename(&db_bak_tmp, &db_bak).await
            .map_err(|e| anyhow::anyhow!("备份落盘失败（{}），已中止更新: {}", db_bak, e))?;
        tracing::info!("数据库已备份到 {}", db_bak);
    }

    // 写新二进制到临时文件（同目录，保证 rename 原子性）
    let tmp_path = current_exe.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp_path, &bytes).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755)).await?;
    }

    // 备份旧二进制（回滚用）；备份失败必须中止，否则失去回滚保障
    let backup_path = current_exe.with_extension("bak");
    tokio::fs::copy(&current_exe, &backup_path).await
        .map_err(|e| anyhow::anyhow!("旧二进制备份失败（{}），已中止更新: {}", backup_path.display(), e))?;

    // 更新标记：记录更新前版本，启动自检后清除
    let marker_path = current_exe.with_extension("updated");
    tokio::fs::write(&marker_path, VERSION).await?;

    // 原子替换
    tokio::fs::rename(&tmp_path, &current_exe).await
        .map_err(|e| anyhow::anyhow!("二进制替换失败: {}（旧版本备份在 {}）", e, backup_path.display()))?;

    // 后台延迟重启（让 HTTP 响应先发出，重启后会自动重新部署脚本）；
    // --no-block 只排队重启任务，命令失败（无 systemd、服务名不对）能立即看到并记日志
    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let service = systemd_service();
        match tokio::process::Command::new("systemctl")
            .args(["--no-block", "restart", &service])
            .status()
            .await
        {
            Ok(s) if s.success() => {}
            Ok(s) => tracing::error!("重启服务 {} 失败（{}）：新版本已就位，请手动重启", service, s),
            Err(e) => tracing::error!("无法执行 systemctl（{}）：新版本已就位，请手动重启服务 {}", e, service),
        }
    });

    Ok(format!("已更新到 {}（SHA256 已校验，数据库与旧二进制已备份），正在重启...", release.tag_name))
}

/// 启动自检：存在更新标记时验证数据库可用，随后清除标记。
/// 若数据库迁移失败，main 会在到达这里之前退出；此时可用 .bak 二进制与 .bak 数据库回滚。
pub async fn confirm_update_marker() {
    let Ok(exe) = std::env::current_exe() else { return };
    let marker = exe.with_extension("updated");
    if let Ok(prev) = tokio::fs::read_to_string(&marker).await {
        tracing::info!("更新自检通过：{} → {}，清除更新标记", prev.trim(), VERSION);
        let _ = tokio::fs::remove_file(&marker).await;
    }
}

/// 比较版本号（语义化版本）
fn is_newer(latest: &str, current: &str) -> bool {
    let parse = |v: &str| -> (u32, u32, u32) {
        let parts: Vec<u32> = v.split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    };

    let l = parse(latest);
    let c = parse(current);

    l.0 > c.0 || (l.0 == c.0 && l.1 > c.1) || (l.0 == c.0 && l.1 == c.1 && l.2 > c.2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_compare() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.1.1"));
    }

    #[test]
    fn sha256sums_check_rejects_tampered_or_unlisted_files() {
        // sha256("abc")；SHA256SUMS 由 CI 的 `sha256sum pve-advanced-tools-*` 生成
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let bin = "pve-advanced-tools-linux-x86_64";
        let sums = format!("{abc}  {bin}.tar.gz\n{abc}  {bin}\n");
        assert!(check_sha256(&sums, bin, b"abc").is_ok());
        assert!(check_sha256(&format!("{}  *{bin}\n", abc.to_uppercase()), bin, b"abc").is_ok(), "binary-mode line, upper-case hash");
        let tampered = check_sha256(&sums, bin, b"abd").unwrap_err().to_string();
        assert!(tampered.starts_with("制品 SHA256 校验失败"), "{tampered}");
        // 只有前缀相同的其他文件不算
        let unlisted = check_sha256(&format!("{abc}  {bin}.tar.gz\n"), bin, b"abc").unwrap_err().to_string();
        assert_eq!(unlisted, format!("SHA256SUMS 中未找到 {bin} 的哈希"));
    }
}
