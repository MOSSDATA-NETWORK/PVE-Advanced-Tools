/// 加密模块：AES-256-GCM + Argon2
/// 密钥从 main.rs 的环境变量或自动生成，不存储在数据库中
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;

/// 加密
pub fn encrypt(plaintext: &str, master_key: &[u8]) -> String {
    let cipher = Aes256Gcm::new_from_slice(master_key).expect("密钥长度错误");
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).expect("加密失败");
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    B64.encode(&combined)
}

/// 解密
pub fn decrypt(encoded: &str, master_key: &[u8]) -> anyhow::Result<String> {
    let combined = B64.decode(encoded)?;
    if combined.len() < 12 {
        return Err(anyhow::anyhow!("密文格式错误"));
    }
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|e| anyhow::anyhow!("密钥错误: {}", e))?;
    let nonce = Nonce::from_slice(&combined[..12]);
    let plaintext = cipher.decrypt(nonce, &combined[12..])
        .map_err(|_| anyhow::anyhow!("解密失败"))?;
    Ok(String::from_utf8(plaintext)?)
}

/// 生成随机 token
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    B64.encode(&bytes)
}

/// Argon2 密码哈希
pub fn hash_password(password: &str) -> String {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("哈希失败")
        .to_string()
}

/// 验证密码
pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// HMAC-SHA256 签名（hex 编码），用于任务包签名
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 常量时间校验 HMAC 签名
pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], expected_hex: &str) -> bool {
    let actual = hmac_sha256_hex(key, msg);
    if actual.len() != expected_hex.len() {
        return false;
    }
    actual
        .bytes()
        .zip(expected_hex.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
