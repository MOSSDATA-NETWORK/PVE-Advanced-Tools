/// Passkey / WebAuthn 模块
/// 简化实现：基于 FIDO2 WebAuthn Level 2 的注册与断言校验
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// RP (Relying Party) 显示名
pub const RP_NAME: &str = "Noqjj";

const E_ALG: &str = "仅支持 ES256（P-256）类型的 Passkey";
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

/// 本次请求解析出的 Relying Party
#[derive(Debug)]
pub struct Rp {
    pub id: String,
    pub origin: String,
}

/// 从环境变量和请求头解析 RP。空的 RP_ORIGIN / RP_ID 视为未设置。
pub fn resolve_rp(headers: &axum::http::HeaderMap) -> Result<Rp, String> {
    let env_origin = std::env::var("RP_ORIGIN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let env_rp_id = std::env::var("RP_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let header_origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    resolve_rp_from(env_origin.as_deref(), env_rp_id.as_deref(), header_origin)
}

/// 纯函数形式，便于测试。env 值由调用方决定是否已去掉空白。
pub fn resolve_rp_from(
    env_origin: Option<&str>,
    env_rp_id: Option<&str>,
    header_origin: Option<&str>,
) -> Result<Rp, String> {
    let (origin, host) = if let Some(pin) = env_origin {
        let (origin, host) = parse_origin(pin)?;
        if let Some(header) = header_origin {
            if loose_norm(header) != origin {
                return Err(format!(
                    "当前访问地址 {header} 与配置的 RP_ORIGIN（{pin}）不一致，请通过 {pin} 访问面板"
                ));
            }
        }
        (origin, host)
    } else {
        let Some(header) = header_origin else {
            return Err("缺少 Origin 请求头，无法确定 Passkey 的域名".to_string());
        };
        parse_origin(header)?
    };

    let id = if let Some(rp_id_raw) = env_rp_id {
        let rp_id = rp_id_raw.to_ascii_lowercase();
        if rp_id != host && !host.ends_with(&format!(".{rp_id}")) {
            return Err(format!(
                "RP_ID（{rp_id}）必须等于访问域名或其上级域名（当前域名：{host}）"
            ));
        }
        rp_id
    } else {
        host
    };
    Ok(Rp { id, origin })
}

fn loose_norm(raw: &str) -> String {
    let trimmed = raw.trim();
    let stripped = trimmed.strip_suffix('/').unwrap_or(trimmed);
    stripped.to_ascii_lowercase()
}

/// 规范化 origin，并取出主机名（不含端口）。失败时 {origin} 用原始字符串。
fn parse_origin(raw: &str) -> Result<(String, String), String> {
    let trimmed = raw.trim();
    let stripped = trimmed.strip_suffix('/').unwrap_or(trimmed);
    let lower = stripped.to_ascii_lowercase();

    let (scheme, rest) = if let Some(r) = lower.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = lower.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(format!("无效的访问地址：{raw}"));
    };

    if rest.is_empty() || rest.chars().any(|c| matches!(c, '/' | '?' | '#' | '@')) {
        return Err(format!("无效的访问地址：{raw}"));
    }
    if rest.starts_with('[') {
        return Err(format!(
            "Passkey 不支持通过 IP 地址访问，请使用域名（HTTPS）访问面板。当前地址：{raw}"
        ));
    }

    let (host, port) = if let Some((host, port_str)) = rest.rsplit_once(':') {
        if port_str.is_empty()
            || port_str.len() > 5
            || !port_str.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!("无效的访问地址：{raw}"));
        }
        let port: u32 = match port_str.parse() {
            Ok(p) if (1..=65535).contains(&p) => p,
            _ => return Err(format!("无效的访问地址：{raw}")),
        };
        (host.to_string(), Some(port))
    } else {
        (rest.to_string(), None)
    };

    let drop_port = matches!((scheme, port), ("https", Some(443)) | ("http", Some(80)));
    let origin = match port {
        Some(p) if !drop_port => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    };

    if !host_ok(&host) {
        return Err(format!("无效的访问地址：{raw}"));
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err(format!(
            "Passkey 不支持通过 IP 地址访问，请使用域名（HTTPS）访问面板。当前地址：{raw}"
        ));
    }
    if scheme == "http" && host != "localhost" {
        return Err(format!(
            "Passkey 需要通过 HTTPS 域名访问面板（本机可用 http://localhost）。当前地址：{raw}"
        ));
    }
    Ok((origin, host))
}

fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
        && host.split('.').all(|label| !label.is_empty())
}

/// 存储的凭据。旧行没有 origin/rp_id，反序列化后为 None，视为不可用。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub created_at: String,
    #[serde(default)]
    pub origin: Option<String>,
    #[serde(default)]
    pub rp_id: Option<String>,
}

fn credential_usable(cred: &StoredCredential) -> bool {
    !cred.credential_id.is_empty()
        && cred.origin.is_some()
        && cred.rp_id.is_some()
        && cose_verifying_key(&cred.public_key).is_ok()
}

/// 至少一条可用凭据。JSON 无法解析时为 false。
pub fn has_usable_credential(json: &str) -> bool {
    let creds: Vec<StoredCredential> = match serde_json::from_str(json) {
        Ok(c) => c,
        Err(_) => return false,
    };
    creds.iter().any(credential_usable)
}

/// 注册挑战
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub challenge: String,
    pub user_id: String,
    pub username: String,
}

/// 认证挑战
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub challenge: String,
    pub allow_credentials: Vec<String>,
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
    /// WebAuthn 使用 clientDataJSON；camelCase 会得到 clientDataJson，两者都接受。
    #[serde(alias = "clientDataJSON")]
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
    #[serde(alias = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    /// base64url(用户 id 的十进制 ASCII)。缺失或 null 在校验阶段拒绝。
    #[serde(default)]
    pub user_handle: Option<String>,
}

/// 生成随机 challenge
pub fn generate_challenge() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64_url_encode(&bytes)
}

struct ParsedAuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    credential_id: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

/// authenticator data：rpIdHash(32) ‖ flags(1) ‖ signCount(4)，
/// AT 时接着 AAGUID(16) ‖ credIdLen(2) ‖ credId ‖ 恰好一个 CBOR 公钥。
/// ED 时剩余部分必须是恰好一个 CBOR map。
fn parse_auth_data(data: &[u8]) -> anyhow::Result<ParsedAuthData> {
    if data.len() < 37 {
        return Err(anyhow::anyhow!("authData 太短"));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[..32]);
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    if flags & BS != 0 && flags & BE == 0 {
        return Err(anyhow::anyhow!("authData 标志位无效"));
    }

    if flags & AT != 0 {
        if data.len() < 55 {
            return Err(anyhow::anyhow!("authData 太短"));
        }
        let cred_len = u16::from_be_bytes([data[53], data[54]]) as usize;
        if !(1..=1023).contains(&cred_len) {
            return Err(anyhow::anyhow!("authData 格式错误"));
        }
        let id_end = 55 + cred_len;
        if data.len() < id_end {
            return Err(anyhow::anyhow!("authData 太短"));
        }
        let credential_id = data[55..id_end].to_vec();
        let (public_key, after) = split_one_cbor(&data[id_end..])?;
        if flags & ED != 0 {
            expect_exact_cbor_map(after)?;
        } else if !after.is_empty() {
            return Err(anyhow::anyhow!("authData 格式错误"));
        }
        return Ok(ParsedAuthData {
            rp_id_hash,
            flags,
            sign_count,
            credential_id: Some(credential_id),
            public_key: Some(public_key),
        });
    }

    if flags & ED != 0 {
        expect_exact_cbor_map(&data[37..])?;
    } else if data.len() != 37 {
        return Err(anyhow::anyhow!("authData 格式错误"));
    }
    Ok(ParsedAuthData {
        rp_id_hash,
        flags,
        sign_count,
        credential_id: None,
        public_key: None,
    })
}

fn split_one_cbor(bytes: &[u8]) -> anyhow::Result<(Vec<u8>, &[u8])> {
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("authData 格式错误"));
    }
    let mut de = serde_cbor::Deserializer::from_slice(bytes);
    let _value = serde_cbor::Value::deserialize(&mut de)
        .map_err(|_| anyhow::anyhow!("authData 格式错误"))?;
    let n = de.byte_offset();
    if n == 0 || n > bytes.len() {
        return Err(anyhow::anyhow!("authData 格式错误"));
    }
    Ok((bytes[..n].to_vec(), &bytes[n..]))
}

fn expect_exact_cbor_map(bytes: &[u8]) -> anyhow::Result<()> {
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("authData 格式错误"));
    }
    let mut de = serde_cbor::Deserializer::from_slice(bytes);
    let value = serde_cbor::Value::deserialize(&mut de)
        .map_err(|_| anyhow::anyhow!("authData 格式错误"))?;
    if de.byte_offset() != bytes.len() {
        return Err(anyhow::anyhow!("authData 格式错误"));
    }
    match value {
        serde_cbor::Value::Map(_) => Ok(()),
        _ => Err(anyhow::anyhow!("authData 格式错误")),
    }
}

fn cose_verifying_key(bytes: &[u8]) -> anyhow::Result<p256::ecdsa::VerifyingKey> {
    let value: serde_cbor::Value = serde_cbor::from_slice(bytes).map_err(|_| anyhow::anyhow!(E_ALG))?;
    let serde_cbor::Value::Map(map) = value else {
        return Err(anyhow::anyhow!(E_ALG));
    };
    let get_int = |k: i128| -> Option<i128> {
        match map.get(&serde_cbor::Value::Integer(k)) {
            Some(serde_cbor::Value::Integer(v)) => Some(*v),
            _ => None,
        }
    };
    if get_int(1) != Some(2) || get_int(3) != Some(-7) || get_int(-1) != Some(1) {
        return Err(anyhow::anyhow!(E_ALG));
    }
    let coord = |k: i128| -> anyhow::Result<[u8; 32]> {
        match map.get(&serde_cbor::Value::Integer(k)) {
            Some(serde_cbor::Value::Bytes(b)) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(b);
                Ok(out)
            }
            _ => Err(anyhow::anyhow!(E_ALG)),
        }
    };
    let x = coord(-2)?;
    let y = coord(-3)?;
    let x_fb: p256::FieldBytes = x.into();
    let y_fb: p256::FieldBytes = y.into();
    let point = p256::EncodedPoint::from_affine_coordinates(&x_fb, &y_fb, false);
    p256::ecdsa::VerifyingKey::from_encoded_point(&point).map_err(|_| anyhow::anyhow!(E_ALG))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn check_client_data(bytes: &[u8], expected_type: &str, challenge: &str) -> anyhow::Result<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| anyhow::anyhow!("clientDataJSON 无效: {e}"))?;
    if value["type"].as_str() != Some(expected_type) {
        return Err(anyhow::anyhow!("无效的 clientData type"));
    }
    if value["challenge"].as_str() != Some(challenge) {
        return Err(anyhow::anyhow!("challenge 不匹配"));
    }
    if value.get("crossOrigin").and_then(|v| v.as_bool()) == Some(true) || value.get("topOrigin").is_some()
    {
        return Err(anyhow::anyhow!("不支持跨域嵌入页面中的 Passkey 请求"));
    }
    Ok(value["origin"].as_str().unwrap_or("").to_string())
}

fn require_up_uv(flags: u8) -> anyhow::Result<()> {
    if flags & UP == 0 {
        return Err(anyhow::anyhow!("User Present 标志未设置"));
    }
    if flags & UV == 0 {
        return Err(anyhow::anyhow!("需要用户验证（PIN、指纹或面容）"));
    }
    Ok(())
}

/// 仅当读到的凭据 JSON 未变，且（会话已验证或尚未绑定 TOTP）时写入。
pub(crate) async fn store_credential_if_eligible(
    pool: &SqlitePool,
    user_id: i64,
    session_verified: bool,
    json_read: Option<&str>,
    new_json: &str,
) -> anyhow::Result<bool> {
    let verified: i64 = if session_verified { 1 } else { 0 };
    let res = sqlx::query(
        "UPDATE users SET passkey_credential = ? WHERE id = ? AND passkey_credential IS ? AND (? = 1 OR TRIM(COALESCE(totp_secret,'')) = '')",
    )
    .bind(new_json)
    .bind(user_id)
    .bind(json_read)
    .bind(verified)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

async fn credential_id_taken(pool: &SqlitePool, cred_id: &[u8]) -> anyhow::Result<bool> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT passkey_credential FROM users WHERE passkey_credential IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    for json in rows {
        let creds: Vec<StoredCredential> = match serde_json::from_str(&json) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if creds.iter().any(|c| c.credential_id == cred_id) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 注册：验证并存储凭据。未完成二次验证的会话不能在已有可用 Passkey 上追加。
pub async fn verify_and_store_credential(
    pool: &SqlitePool,
    user_id: i64,
    resp: &RegistrationResponse,
    expected_challenge: &str,
    rp: &Rp,
    session_verified: bool,
) -> anyhow::Result<()> {
    let client_data_bytes = base64_url_decode(&resp.response.client_data_json)?;
    let origin = check_client_data(&client_data_bytes, "webauthn.create", expected_challenge)?;
    if origin != rp.origin {
        return Err(anyhow::anyhow!("origin 不匹配: 期望 {}, 实际 {}", rp.origin, origin));
    }

    let att_obj = base64_url_decode(&resp.response.attestation_object)?;
    let auth_data = attestation_auth_data(&att_obj)?;
    let parsed = parse_auth_data(&auth_data)?;
    if parsed.rp_id_hash != sha256(rp.id.as_bytes()) {
        return Err(anyhow::anyhow!("rpIdHash 不匹配"));
    }
    require_up_uv(parsed.flags)?;
    let (credential_id, public_key) = match (parsed.credential_id, parsed.public_key) {
        (Some(id), Some(key)) => (id, key),
        _ => return Err(anyhow::anyhow!("缺少凭据数据")),
    };
    let raw_id = base64_url_decode(&resp.raw_id)?;
    if credential_id != raw_id {
        return Err(anyhow::anyhow!("凭据 ID 不一致"));
    }
    if credential_id_taken(pool, &credential_id).await? {
        return Err(anyhow::anyhow!("该 Passkey 已注册"));
    }
    cose_verifying_key(&public_key)?;

    let json_read: Option<String> = sqlx::query_scalar(
        "SELECT passkey_credential FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    if !session_verified && json_read.as_deref().is_some_and(has_usable_credential) {
        return Err(anyhow::anyhow!("请先完成二次验证"));
    }

    let mut creds: Vec<StoredCredential> = match json_read.as_deref() {
        Some(s) => serde_json::from_str(s).unwrap_or_default(),
        None => Vec::new(),
    };
    creds.push(StoredCredential {
        credential_id,
        public_key,
        sign_count: parsed.sign_count,
        created_at: chrono::Utc::now().to_rfc3339(),
        origin: Some(rp.origin.clone()),
        rp_id: Some(rp.id.clone()),
    });
    let new_json = serde_json::to_string(&creds)?;
    if !store_credential_if_eligible(pool, user_id, session_verified, json_read.as_deref(), &new_json).await? {
        return Err(anyhow::anyhow!("账户状态已变化，请刷新后重试"));
    }
    Ok(())
}

fn attestation_auth_data(att_obj: &[u8]) -> anyhow::Result<Vec<u8>> {
    let att_data: serde_cbor::Value = serde_cbor::from_slice(att_obj)
        .map_err(|_| anyhow::anyhow!("attestationObject 格式错误"))?;
    let serde_cbor::Value::Map(m) = att_data else {
        return Err(anyhow::anyhow!("attestationObject 格式错误"));
    };
    match m.get(&serde_cbor::Value::Text("authData".to_string())) {
        Some(serde_cbor::Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(anyhow::anyhow!("缺少 authData")),
    }
}

fn cred_origin_error(origin: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "该 Passkey 绑定于 {origin}，请通过该地址登录，或使用用户名 + 密码 + TOTP 登录后重新注册"
    )
}

/// 认证：按 raw_id 查找可用凭据并验证断言。不使用请求里的 RP。
pub async fn verify_authentication(
    pool: &SqlitePool,
    resp: &AuthenticationResponse,
    expected_challenge: &str,
) -> anyhow::Result<Option<i64>> {
    let client_data_bytes = base64_url_decode(&resp.response.client_data_json)?;
    let client_origin = check_client_data(&client_data_bytes, "webauthn.get", expected_challenge)?;
    let raw_id = base64_url_decode(&resp.raw_id)?;

    let users: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, passkey_credential FROM users WHERE passkey_credential IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;

    let mut found_user_id = None;
    let mut found_cred = None;
    for (uid, cred_json) in &users {
        let creds: Vec<StoredCredential> = match serde_json::from_str(cred_json) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for cred in creds {
            if cred.credential_id == raw_id && credential_usable(&cred) {
                found_user_id = Some(*uid);
                found_cred = Some(cred);
                break;
            }
        }
        if found_cred.is_some() {
            break;
        }
    }

    let user_id = found_user_id.ok_or_else(|| anyhow::anyhow!("未找到凭据"))?;
    let cred = found_cred.ok_or_else(|| anyhow::anyhow!("未找到凭据"))?;
    let cred_origin = cred.origin.clone().unwrap_or_default();
    let cred_rp_id = cred.rp_id.clone().unwrap_or_default();

    if client_origin != cred_origin {
        return Err(cred_origin_error(&cred_origin));
    }
    if let Ok(pin_raw) = std::env::var("RP_ORIGIN") {
        if !pin_raw.trim().is_empty() {
            let (pin, _) = parse_origin(&pin_raw).map_err(|e| anyhow::anyhow!(e))?;
            if pin != cred_origin {
                return Err(cred_origin_error(&cred_origin));
            }
        }
    }

    let auth_data = base64_url_decode(&resp.response.authenticator_data)?;
    let parsed = parse_auth_data(&auth_data)?;
    if parsed.rp_id_hash != sha256(cred_rp_id.as_bytes()) {
        return Err(anyhow::anyhow!("rpIdHash 不匹配"));
    }
    require_up_uv(parsed.flags)?;

    let handle = resp
        .response
        .user_handle
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Passkey 用户标识不匹配"))?;
    let handle_bytes = base64_url_decode(handle).map_err(|_| anyhow::anyhow!("Passkey 用户标识不匹配"))?;
    if handle_bytes != user_id.to_string().into_bytes() {
        return Err(anyhow::anyhow!("Passkey 用户标识不匹配"));
    }

    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&client_data_bytes);
    let client_data_hash = hasher.finalize();
    let mut verification_data = auth_data.clone();
    verification_data.extend_from_slice(&client_data_hash);

    let signature = base64_url_decode(&resp.response.signature)?;
    let verifying_key = cose_verifying_key(&cred.public_key)?;
    use p256::ecdsa::signature::Verifier;
    let sig = p256::ecdsa::Signature::from_der(&signature)
        .or_else(|_| p256::ecdsa::Signature::from_slice(&signature))
        .map_err(|e| anyhow::anyhow!("签名解析失败: {}", e))?;
    verifying_key
        .verify(&verification_data, &sig)
        .map_err(|_| anyhow::anyhow!("签名验证失败"))?;

    let new_count = parsed.sign_count;
    if (new_count != 0 || cred.sign_count != 0) && new_count <= cred.sign_count {
        return Err(anyhow::anyhow!("sign_count 回退，可能为克隆凭据"));
    }

    let cred_json_str: String = sqlx::query_scalar(
        "SELECT passkey_credential FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    let mut creds: Vec<StoredCredential> = serde_json::from_str(&cred_json_str).unwrap_or_default();
    if let Some(c) = creds.iter_mut().find(|c| c.credential_id == raw_id) {
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

fn ids_from_json(json: &str, usable_only: bool) -> Vec<String> {
    let creds: Vec<StoredCredential> = serde_json::from_str(json).unwrap_or_default();
    creds
        .into_iter()
        .filter(|c| !c.credential_id.is_empty() && (!usable_only || credential_usable(c)))
        .map(|c| base64_url_encode(&c.credential_id))
        .collect()
}

async fn load_credential_ids(pool: &SqlitePool, username: &str, usable_only: bool) -> Vec<String> {
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT passkey_credential FROM users WHERE username = ? AND passkey_credential IS NOT NULL",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    match result {
        Some((json,)) => ids_from_json(&json, usable_only),
        None => vec![],
    }
}

/// 用户已保存的凭据 ID（含尚不可用的旧行），用于注册时 excludeCredentials。
pub async fn get_user_credential_ids(pool: &SqlitePool, username: &str) -> Vec<String> {
    load_credential_ids(pool, username, false).await
}

/// 当前可以登录的凭据 ID。
pub async fn get_usable_credential_ids(pool: &SqlitePool, username: &str) -> Vec<String> {
    load_credential_ids(pool, username, true).await
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}
