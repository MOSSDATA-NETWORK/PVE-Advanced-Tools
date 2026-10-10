//! 版本管理模块
//! - 编译时嵌入版本号（语义化版本，自首个版本启用）
//! - GitHub API 检查新版本
//! - 一键更新：SHA256SUMS 校验 + 原子替换 + 更新前备份 SQLite 与旧二进制
//! - 更新标记：启动时校验，迁移失败可从 .bak 恢复（见 README 回滚说明）
use serde::{Deserialize, Serialize};

/// 当前版本（编译时从 Cargo.toml 读取）
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// 检测脚本版本（脚本内容变化时递增，用于触发自动重新部署）
pub const SCRIPT_VERSION: &str = "3";

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

    if !resp.status().is_success() {
        return Ok(VersionInfo {
            current: VERSION.to_string(),
            latest: None,
            update_available: false,
            release_url: None,
            release_notes: None,
            published_at: None,
        });
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

/// 更新签名公钥（ed25519，hex 64 字符）：配置后发布必须带 <制品>.sig 签名。
/// 环境变量已设置但格式错误 → 报错失败关闭（不得静默降级为仅哈希校验）
fn update_sign_pubkey() -> anyhow::Result<Option<[u8; 32]>> {
    // var_os 区分「未设置」与「非法值」：已设置但非 UTF-8 同样失败关闭
    let Some(raw) = std::env::var_os("UPDATE_SIGN_PUBKEY") else { return Ok(None) };
    let hex = raw.to_str()
        .ok_or_else(|| anyhow::anyhow!("UPDATE_SIGN_PUBKEY 含非 UTF-8 字符"))?
        .trim();
    if hex.len() != 64 {
        return Err(anyhow::anyhow!("UPDATE_SIGN_PUBKEY 格式错误（需要 64 位 hex）"));
    }
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow::anyhow!("UPDATE_SIGN_PUBKEY 含非 hex 字符"))?;
    bytes.try_into()
        .map(Some)
        .map_err(|_| anyhow::anyhow!("UPDATE_SIGN_PUBKEY 长度错误"))
}

/// 校验制品 ed25519 签名（sig 支持 raw 64 字节 / hex / base64）
fn verify_signature(pubkey: &[u8; 32], data: &[u8], sig_bytes: &[u8]) -> anyhow::Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| anyhow::anyhow!("签名公钥无效: {}", e))?;
    let sig_raw: Vec<u8> = if sig_bytes.len() == 64 {
        sig_bytes.to_vec()
    } else if let Ok(s) = std::str::from_utf8(sig_bytes) {
        let s = s.trim();
        if s.len() == 128 {
            (0..128).step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
                .collect::<Result<_, _>>()
                .map_err(|_| anyhow::anyhow!("签名 hex 解析失败"))?
        } else {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(s)
                .map_err(|_| anyhow::anyhow!("签名格式无法识别（支持 raw/hex/base64）"))?
        }
    } else {
        return Err(anyhow::anyhow!("签名格式无法识别"));
    };
    let sig = Signature::from_slice(&sig_raw)
        .map_err(|e| anyhow::anyhow!("签名长度错误: {}", e))?;
    key.verify_strict(data, &sig)
        .map_err(|_| anyhow::anyhow!("制品签名校验失败，拒绝更新"))
}

/// 下载并校验 SHA256SUMS 中对应制品的哈希；配置签名公钥时强制验签
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

    let expected = sums_text.lines()
        .find_map(|line| {
            let mut it = line.split_whitespace();
            let hash = it.next()?;
            let fname = it.next()?;
            if fname.trim_start_matches('*') == asset_name { Some(hash.to_string()) } else { None }
        })
        .ok_or_else(|| anyhow::anyhow!("SHA256SUMS 中未找到 {} 的哈希", asset_name))?;

    let bytes = client.get(&asset.browser_download_url)
        .header("User-Agent", user_agent())
        .send().await?
        .error_for_status()?
        .bytes().await?;

    use sha2::Digest;
    let actual = format!("{:x}", sha2::Sha256::digest(&bytes));
    if !actual.eq_ignore_ascii_case(&expected) {
        return Err(anyhow::anyhow!("制品 SHA256 校验失败（期望 {}，实际 {}），已中止更新", expected, actual));
    }

    // 签名校验强制开启（SHA256SUMS 与制品同源，不防发布篡改）：
    // 未配置 UPDATE_SIGN_PUBKEY 时拒绝更新，而不是降级为仅哈希校验
    match update_sign_pubkey()?.ok_or_else(|| anyhow::anyhow!(
        "未配置 UPDATE_SIGN_PUBKEY 验签公钥，拒绝更新（SHA256SUMS 与制品同源不足以防篡改）"
    ))? {
        pubkey => {
            let sig_name = format!("{}.sig", asset_name);
            let sig_asset = release.assets.iter().find(|a| a.name == sig_name)
                .ok_or_else(|| anyhow::anyhow!("已配置签名公钥但发布缺少 {}，拒绝更新", sig_name))?;
            let sig_bytes = client.get(&sig_asset.browser_download_url)
                .header("User-Agent", user_agent())
                .send().await?
                .error_for_status()?
                .bytes().await?;
            verify_signature(&pubkey, &bytes, &sig_bytes)?;
            tracing::info!("制品签名校验通过");
        }
    }
    Ok(bytes.to_vec())
}

/// 更新锁：同时只允许一个更新流程
static UPDATE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

/// 执行更新：校验哈希 → 一致性备份数据库与旧二进制 → 原子替换 → 延迟重启
pub async fn perform_update(pool: &sqlx::SqlitePool) -> anyhow::Result<String> {
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
    let bytes = download_verified(&client, &release, &asset_name).await?;

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

    // 后台延迟重启（让 HTTP 响应先发出，重启后会自动重新部署脚本）
    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let _ = tokio::process::Command::new("systemctl")
            .args(["restart", &systemd_service()])
            .spawn();
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
}
