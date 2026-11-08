/// TOTP 身份验证器支持
use totp_rs::{Algorithm, Secret, TOTP};

const ISSUER: &str = "Noqjj";

/// 生成 TOTP 密钥，返回 base32 字符串
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 20]; // 160 bits
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bytes)
}

/// 生成 otpauth URI（用于二维码）
pub fn get_otpauth_uri(username: &str, secret: &str) -> String {
    format!("otpauth://totp/{}:{}?secret={}&issuer={}&digits=6&period=30&algorithm=SHA1",
            ISSUER, username, secret, ISSUER)
}

/// 验证 TOTP code（skew=1 允许前后1个时间窗口的偏差）
pub fn verify_code(secret: &str, code: &str) -> bool {
    // secret 存储为 base32，解码为 raw bytes
    let secret_bytes = match base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret) {
        Some(b) => b,
        None => return false,
    };
    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes, Some(ISSUER.to_string()), "user".to_string()) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    totp.check(code, timestamp)
}

/// 当前时间窗口的验证码，算法与 verify_code 相同。
#[cfg(test)]
pub fn current_code(secret: &str) -> String {
    let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
        .expect("totp secret");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(ISSUER.to_string()),
        "user".to_string(),
    )
    .expect("totp");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    totp.generate(timestamp)
}
