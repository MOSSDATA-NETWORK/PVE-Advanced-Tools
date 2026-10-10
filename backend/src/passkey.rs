/// Passkey / WebAuthn 模块
/// 简化实现：基于 FIDO2 WebAuthn Level 3
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// RP (Relying Party) 配置
pub const RP_NAME: &str = "Noqjj";

/// 获取 RP_ID（从环境变量或默认 localhost）
pub fn get_rp_id() -> String {
    std::env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string())
}

/// 获取期望的 Origin
pub fn get_expected_origin() -> String {
    if let Ok(origin) = std::env::var("RP_ORIGIN") {
        return origin;
    }
    let tls = std::env::var("TLS_CERT").is_ok()
        || std::env::var("BEHIND_TLS_PROXY").map(|v| v == "1" || v == "true").unwrap_or(false);
    let scheme = if tls { "https" } else { "http" };
    // 从 HOST 环境变量获取域名，默认 localhost
    let host = std::env::var("HOST").unwrap_or_else(|_| "localhost".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3210".to_string());
    format!("{}://{}:{}", scheme, host, port)
}

/// 存储的凭据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,      // COSE 公钥的 CBOR 编码
    pub sign_count: u32,
    pub created_at: String,
}

/// 注册挑战
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub challenge: String,         // base64url
    pub user_id: String,
    pub username: String,
}

/// 认证挑战
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub challenge: String,         // base64url
    pub allow_credentials: Vec<String>, // credential_id base64url
}

/// 浏览器返回的注册结果
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponse {
    pub id: String,
    pub raw_id: String,
    pub response: RegistrationResponseData,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponseData {
    pub attestation_object: String,
    pub client_data_json: String,
}

/// 浏览器返回的认证结果
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponse {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticationResponseData,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponseData {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

/// 生成随机 challenge
pub fn generate_challenge() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64_url_encode(&bytes)
}

/// 注册：验证并存储凭据
pub async fn verify_and_store_credential(
    pool: &SqlitePool,
    user_id: i64,
    resp: &RegistrationResponse,
    expected_challenge: &str,
) -> anyhow::Result<()> {
    // 1. 解码 client_data_json，验证 challenge 和 origin
    let client_data = base64_url_decode(&resp.response.client_data_json)?;
    let client_data_str = String::from_utf8(client_data)?;
    let client_value: serde_json::Value = serde_json::from_str(&client_data_str)?;

    // 验证 type
    if client_value["type"].as_str() != Some("webauthn.create") {
        return Err(anyhow::anyhow!("无效的 clientData type"));
    }

    // 验证 challenge
    if client_value["challenge"].as_str() != Some(expected_challenge) {
        return Err(anyhow::anyhow!("challenge 不匹配"));
    }

    // 验证 origin（严格匹配）
    let origin = client_value["origin"].as_str().unwrap_or("");
    let expected_origin = get_expected_origin();
    if origin != expected_origin {
        return Err(anyhow::anyhow!("origin 不匹配: 期望 {}, 实际 {}", expected_origin, origin));
    }

    // 2. 解码 attestation_object，提取公钥
    let att_obj = base64_url_decode(&resp.response.attestation_object)?;
    let att_data: serde_cbor::Value = serde_cbor::from_slice(&att_obj)?;

    // 从 attStmt.authData 中提取公钥
    let auth_data = if let serde_cbor::Value::Map(m) = &att_data {
        if let Some(serde_cbor::Value::Bytes(b)) = m.get(&serde_cbor::Value::Text("authData".to_string())) {
            b.clone()
        } else {
            return Err(anyhow::anyhow!("缺少 authData"));
        }
    } else {
        return Err(anyhow::anyhow!("attestationObject 格式错误"));
    };

    // 解析 authenticatorData
    if auth_data.len() < 37 {
        return Err(anyhow::anyhow!("authData 太短"));
    }

    // 提取 credential_id (从 offset 55 开始，前面 37 字节是固定头)
    // auth_data[0..32] = rpIdHash
    // auth_data[32] = flags
    // auth_data[33..37] = signCount
    // auth_data[37..39] = credentialIdLength (big-endian u16)
    // auth_data[39..39+len] = credentialId
    // auth_data[39+len..] = credentialPublicKey (COSE)

    let cred_id_len = ((auth_data[37] as usize) << 8) | (auth_data[38] as usize);
    if auth_data.len() < 39 + cred_id_len {
        return Err(anyhow::anyhow!("authData 长度不足"));
    }

    let credential_id = auth_data[39..39 + cred_id_len].to_vec();
    let public_key_cbor = auth_data[39 + cred_id_len..].to_vec();

    // 验证标志位 (User Present = bit 0)
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(anyhow::anyhow!("User Present 标志未设置"));
    }

    // 3. 存储凭据
    let cred = StoredCredential {
        credential_id: credential_id.clone(),
        public_key: public_key_cbor,
        sign_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let cred_json = serde_json::to_string(&cred)?;

    // 检查是否已存在
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT passkey_credential FROM users WHERE id = ? AND passkey_credential IS NOT NULL"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    if let Some((existing_json,)) = existing {
        // 追加到已有凭据列表
        let mut creds: Vec<StoredCredential> = serde_json::from_str(&existing_json).unwrap_or_default();
        creds.push(cred);
        let new_json = serde_json::to_string(&creds)?;
        sqlx::query("UPDATE users SET passkey_credential = ? WHERE id = ?")
            .bind(&new_json)
            .bind(user_id)
            .execute(pool)
            .await?;
    } else {
        let creds = vec![cred];
        let new_json = serde_json::to_string(&creds)?;
        sqlx::query("UPDATE users SET passkey_credential = ? WHERE id = ?")
            .bind(&new_json)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// 认证：验证签名
pub async fn verify_authentication(
    pool: &SqlitePool,
    resp: &AuthenticationResponse,
    expected_challenge: &str,
) -> anyhow::Result<Option<i64>> {
    // 1. 解码 client_data_json
    let client_data = base64_url_decode(&resp.response.client_data_json)?;
    let client_data_str = String::from_utf8(client_data)?;
    let client_value: serde_json::Value = serde_json::from_str(&client_data_str)?;

    if client_value["type"].as_str() != Some("webauthn.get") {
        return Err(anyhow::anyhow!("无效的 clientData type"));
    }

    if client_value["challenge"].as_str() != Some(expected_challenge) {
        return Err(anyhow::anyhow!("challenge 不匹配"));
    }

    // 验证 origin
    let origin = client_value["origin"].as_str().unwrap_or("");
    let expected_origin = get_expected_origin();
    if origin != expected_origin {
        return Err(anyhow::anyhow!("origin 不匹配: 期望 {}, 实际 {}", expected_origin, origin));
    }

    // 2. 查找凭据
    let raw_id = base64_url_decode(&resp.raw_id)?;

    // 在所有用户中查找匹配的凭据
    let users: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, passkey_credential FROM users WHERE passkey_credential IS NOT NULL"
    )
    .fetch_all(pool)
    .await?;

    let mut found_user_id = None;
    let mut found_cred = None;
    let mut found_cred_index = None;

    for (uid, cred_json) in &users {
        let creds: Vec<StoredCredential> = match serde_json::from_str(cred_json) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (i, cred) in creds.iter().enumerate() {
            if cred.credential_id == raw_id {
                found_user_id = Some(*uid);
                found_cred = Some(cred.clone());
                found_cred_index = Some(i);
                break;
            }
        }
        if found_cred.is_some() { break; }
    }

    let user_id = found_user_id.ok_or_else(|| anyhow::anyhow!("未找到凭据"))?;
    let cred = found_cred.ok_or_else(|| anyhow::anyhow!("未找到凭据"))?;
    let cred_idx = found_cred_index.unwrap();

    // 3. 解析 authenticatorData 并验证 rpIdHash
    let auth_data = base64_url_decode(&resp.response.authenticator_data)?;
    if auth_data.len() < 37 {
        return Err(anyhow::anyhow!("authenticatorData 太短"));
    }

    // 验证 rpIdHash
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(get_rp_id().as_bytes());
    let expected_hash = hasher.finalize();
    if &auth_data[0..32] != expected_hash.as_slice() {
        return Err(anyhow::anyhow!("rpIdHash 不匹配"));
    }

    // 验证 User Present 标志
    if auth_data[32] & 0x01 == 0 {
        return Err(anyhow::anyhow!("User Present 标志未设置"));
    }

    // 4. 验证签名
    // 构造验证数据 = authenticatorData + SHA256(clientDataJSON)
    let client_data_bytes = base64_url_decode(&resp.response.client_data_json)?;
    let mut hasher = Sha256::new();
    hasher.update(&client_data_bytes);
    let client_data_hash = hasher.finalize();

    let mut verification_data = auth_data.clone();
    verification_data.extend_from_slice(&client_data_hash);

    let signature = base64_url_decode(&resp.response.signature)?;

    // 从 COSE 公钥中提取 P-256 公钥
    let cose_key: serde_cbor::Value = serde_cbor::from_slice(&cred.public_key)?;
    let (x, y) = extract_p256_coords(&cose_key)?;

    use p256::ecdsa::{VerifyingKey, signature::Verifier};
    use p256::EncodedPoint;
    let encoded_point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|e| anyhow::anyhow!("公钥解析失败: {}", e))?;

    let sig = p256::ecdsa::Signature::from_der(&signature)
        .or_else(|_| p256::ecdsa::Signature::from_slice(&signature))
        .map_err(|e| anyhow::anyhow!("签名解析失败: {}", e))?;

    verifying_key.verify(&verification_data, &sig)
        .map_err(|_| anyhow::anyhow!("签名验证失败"))?;

    // 5. 验证并更新 sign_count
    let new_count = ((auth_data[33] as u32) << 24)
        | ((auth_data[34] as u32) << 16)
        | ((auth_data[35] as u32) << 8)
        | (auth_data[36] as u32);

    // sign_count 必须大于存储值（防克隆凭据）
    if new_count > 0 && cred.sign_count > 0 && new_count <= cred.sign_count {
        return Err(anyhow::anyhow!("sign_count 回退，可能为克隆凭据"));
    }

    // 更新存储的凭据
    let cred_json_str: String = sqlx::query_scalar(
        "SELECT passkey_credential FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let mut creds: Vec<StoredCredential> = serde_json::from_str(&cred_json_str).unwrap_or_default();
    if let Some(c) = creds.get_mut(cred_idx) {
        c.sign_count = new_count;
    }
    let updated_json = serde_json::to_string(&creds)?;
    sqlx::query("UPDATE users SET passkey_credential = ? WHERE id = ?")
        .bind(&updated_json)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(Some(user_id))
}

/// 获取用户的凭据 ID 列表（用于认证请求）
pub async fn get_user_credential_ids(pool: &SqlitePool, username: &str) -> Vec<String> {
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT passkey_credential FROM users WHERE username = ? AND passkey_credential IS NOT NULL"
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    match result {
        Some((json,)) => {
            let creds: Vec<StoredCredential> = serde_json::from_str(&json).unwrap_or_default();
            creds.iter().map(|c| base64_url_encode(&c.credential_id)).collect()
        }
        None => vec![],
    }
}

/// 删除用户的所有 Passkey 凭据
pub async fn delete_credentials(pool: &SqlitePool, user_id: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET passkey_credential = NULL WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// 从 COSE 公钥中提取 P-256 坐标
fn extract_p256_coords(cose: &serde_cbor::Value) -> anyhow::Result<(p256::FieldBytes, p256::FieldBytes)> {
    let map = match cose {
        serde_cbor::Value::Map(m) => m,
        _ => return Err(anyhow::anyhow!("COSE 公钥格式错误")),
    };

    // COSE Key 参数: -2 = x, -3 = y
    let x = map.get(&serde_cbor::Value::Integer(-2))
        .and_then(|v| if let serde_cbor::Value::Bytes(b) = v { Some(b) } else { None })
        .ok_or_else(|| anyhow::anyhow!("缺少 x 坐标"))?;
    let y = map.get(&serde_cbor::Value::Integer(-3))
        .and_then(|v| if let serde_cbor::Value::Bytes(b) = v { Some(b) } else { None })
        .ok_or_else(|| anyhow::anyhow!("缺少 y 坐标"))?;

    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(x);
    y_bytes.copy_from_slice(y);

    Ok((x_bytes.into(), y_bytes.into()))
}

// Base64 URL 编码/解码 (无 padding)
fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}
