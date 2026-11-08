use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tower::ServiceExt;

use crate::passkey::{
    verify_and_store_credential, verify_authentication, AuthenticationResponse, RegistrationResponse,
    Rp, StoredCredential,
};

const ORIGIN: &str = "https://pve.example.com";
const RP_ID: &str = "pve.example.com";
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;
const BS: u8 = 0x10;
const ED: u8 = 0x80;

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn cose_key(x: &[u8], y: &[u8], kty: i128, alg: i128) -> Vec<u8> {
    let mut m = BTreeMap::new();
    m.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(kty));
    m.insert(serde_cbor::Value::Integer(3), serde_cbor::Value::Integer(alg));
    m.insert(serde_cbor::Value::Integer(-1), serde_cbor::Value::Integer(1));
    m.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(x.to_vec()));
    m.insert(serde_cbor::Value::Integer(-3), serde_cbor::Value::Bytes(y.to_vec()));
    serde_cbor::to_vec(&serde_cbor::Value::Map(m)).unwrap()
}

struct SoftKey {
    signing: p256::ecdsa::SigningKey,
    cose: Vec<u8>,
}

impl SoftKey {
    fn generate() -> Self {
        let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let pt = signing.verifying_key().to_encoded_point(false);
        let x = pt.x().unwrap();
        let y = pt.y().unwrap();
        let cose = cose_key(&x[..], &y[..], 2, -7);
        Self { signing, cose }
    }

    fn sign(&self, auth_data: &[u8], client_json: &str) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let mut msg = auth_data.to_vec();
        msg.extend_from_slice(&sha256(client_json.as_bytes()));
        let sig: p256::ecdsa::Signature = self.signing.sign(&msg);
        sig.to_der().as_bytes().to_vec()
    }
}

fn auth_data(rp_id: &str, flags: u8, sign_count: u32, cred: Option<(&[u8], &[u8])>, extra: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&sha256(rp_id.as_bytes()));
    d.push(flags);
    d.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((cred_id, cose)) = cred {
        d.extend_from_slice(&[0xA5; 16]); // 非零 AAGUID
        d.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        d.extend_from_slice(cred_id);
        d.extend_from_slice(cose);
    }
    d.extend_from_slice(extra);
    d
}

fn attestation(auth_data: &[u8]) -> Vec<u8> {
    let mut m = BTreeMap::new();
    m.insert(serde_cbor::Value::Text("fmt".into()), serde_cbor::Value::Text("none".into()));
    m.insert(serde_cbor::Value::Text("attStmt".into()), serde_cbor::Value::Map(BTreeMap::new()));
    m.insert(serde_cbor::Value::Text("authData".into()), serde_cbor::Value::Bytes(auth_data.to_vec()));
    serde_cbor::to_vec(&serde_cbor::Value::Map(m)).unwrap()
}

fn extension_map() -> Vec<u8> {
    let mut m = BTreeMap::new();
    m.insert(serde_cbor::Value::Text("credProtect".into()), serde_cbor::Value::Integer(1));
    serde_cbor::to_vec(&serde_cbor::Value::Map(m)).unwrap()
}

fn client_json(typ: &str, challenge: &str, origin: &str, extra: Option<&str>) -> String {
    match extra {
        Some(e) => format!(r#"{{"type":"{typ}","challenge":"{challenge}","origin":"{origin}",{e}}}"#),
        None => format!(r#"{{"type":"{typ}","challenge":"{challenge}","origin":"{origin}"}}"#),
    }
}

fn registration(
    cred_id: &[u8],
    raw_id: &[u8],
    auth_data: &[u8],
    challenge: &str,
    origin: &str,
    typ: &str,
    extra: Option<&str>,
) -> RegistrationResponse {
    let client = client_json(typ, challenge, origin, extra);
    let v = json!({
        "id": b64(cred_id),
        "rawId": b64(raw_id),
        "type": "public-key",
        "response": {
            "attestationObject": b64(&attestation(auth_data)),
            "clientDataJSON": b64(client.as_bytes()),
        }
    });
    serde_json::from_value(v).unwrap()
}

fn assertion_json(
    key: &SoftKey,
    cred_id: &[u8],
    rp_id: &str,
    flags: u8,
    count: u32,
    challenge: &str,
    origin: &str,
    user_handle: Option<&str>,
    bad_sig: bool,
) -> Value {
    let data = auth_data(rp_id, flags, count, None, &[]);
    let client = client_json("webauthn.get", challenge, origin, None);
    let mut sig = key.sign(&data, &client);
    if bad_sig {
        sig = vec![0u8; 64];
    }
    let mut response = json!({
        "authenticatorData": b64(&data),
        "clientDataJSON": b64(client.as_bytes()),
        "signature": b64(&sig),
    });
    if let Some(handle) = user_handle {
        response["userHandle"] = json!(handle);
    }
    json!({
        "id": b64(cred_id),
        "rawId": b64(cred_id),
        "type": "public-key",
        "response": response,
    })
}

fn assertion(
    key: &SoftKey,
    cred_id: &[u8],
    rp_id: &str,
    flags: u8,
    count: u32,
    challenge: &str,
    origin: &str,
    user_handle: Option<&str>,
    bad_sig: bool,
) -> AuthenticationResponse {
    serde_json::from_value(assertion_json(
        key, cred_id, rp_id, flags, count, challenge, origin, user_handle, bad_sig,
    ))
    .unwrap()
}

fn rp() -> Rp {
    Rp { id: RP_ID.into(), origin: ORIGIN.into() }
}

async fn memory_db() -> SqlitePool {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    super::run_migrations(&pool).await.unwrap();
    pool
}

async fn stored(pool: &SqlitePool, user_id: i64) -> Vec<StoredCredential> {
    let json: Option<String> = sqlx::query_scalar("SELECT passkey_credential FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    match json {
        Some(s) => serde_json::from_str(&s).unwrap_or_default(),
        None => Vec::new(),
    }
}

fn e_ip(origin: &str) -> String {
    format!("Passkey 不支持通过 IP 地址访问，请使用域名（HTTPS）访问面板。当前地址：{origin}")
}
fn e_https(origin: &str) -> String {
    format!("Passkey 需要通过 HTTPS 域名访问面板（本机可用 http://localhost）。当前地址：{origin}")
}
fn e_fmt(origin: &str) -> String {
    format!("无效的访问地址：{origin}")
}

#[tokio::test]
async fn resolve_rp_from_cases() {
    use crate::passkey::resolve_rp_from;

    let r = resolve_rp_from(None, None, Some("https://pve.example.com")).unwrap();
    assert_eq!(r.origin, "https://pve.example.com");
    assert_eq!(r.id, "pve.example.com");

    let r = resolve_rp_from(None, None, Some("https://pve.example.com:8443")).unwrap();
    assert_eq!(r.origin, "https://pve.example.com:8443");
    assert_eq!(r.id, "pve.example.com");

    let r = resolve_rp_from(None, None, Some("http://localhost:3210")).unwrap();
    assert_eq!(r.origin, "http://localhost:3210");
    assert_eq!(r.id, "localhost");

    let ip = "http://192.168.1.10:3210";
    assert_eq!(resolve_rp_from(None, None, Some(ip)).unwrap_err(), e_ip(ip));
    let ip = "https://10.0.0.5";
    assert_eq!(resolve_rp_from(None, None, Some(ip)).unwrap_err(), e_ip(ip));
    let ip = "https://[::1]";
    assert_eq!(resolve_rp_from(None, None, Some(ip)).unwrap_err(), e_ip(ip));

    let http = "http://pve.example.com";
    assert_eq!(resolve_rp_from(None, None, Some(http)).unwrap_err(), e_https(http));
    assert_eq!(
        resolve_rp_from(None, None, None).unwrap_err(),
        "缺少 Origin 请求头，无法确定 Passkey 的域名"
    );
    assert_eq!(resolve_rp_from(None, None, Some("null")).unwrap_err(), e_fmt("null"));
    let path = "https://pve.example.com/admin";
    assert_eq!(resolve_rp_from(None, None, Some(path)).unwrap_err(), e_fmt(path));

    let r = resolve_rp_from(Some(ORIGIN), None, Some(ORIGIN)).unwrap();
    assert_eq!(r.origin, ORIGIN);
    assert_eq!(r.id, RP_ID);

    let r = resolve_rp_from(Some("https://pve.example.com/"), None, None).unwrap();
    assert_eq!(r.origin, ORIGIN);
    assert_eq!(r.id, RP_ID);

    let r = resolve_rp_from(Some("https://pve.example.com:443"), None, Some(ORIGIN)).unwrap();
    assert_eq!(r.origin, ORIGIN);
    assert_eq!(r.id, RP_ID);

    let pin = "https://pve.example.com";
    let header = "https://other.example";
    assert_eq!(
        resolve_rp_from(Some(pin), None, Some(header)).unwrap_err(),
        format!("当前访问地址 {header} 与配置的 RP_ORIGIN（{pin}）不一致，请通过 {pin} 访问面板")
    );

    let r = resolve_rp_from(None, Some("example.com"), Some(ORIGIN)).unwrap();
    assert_eq!(r.id, "example.com");
    assert_eq!(r.origin, ORIGIN);

    assert_eq!(
        resolve_rp_from(None, Some("ample.com"), Some(ORIGIN)).unwrap_err(),
        "RP_ID（ample.com）必须等于访问域名或其上级域名（当前域名：pve.example.com）"
    );

    let r = resolve_rp_from(None, Some(RP_ID), Some(ORIGIN)).unwrap();
    assert_eq!(r.id, RP_ID);
    assert_eq!(r.origin, ORIGIN);
}

#[tokio::test]
async fn registration_cases() {
    let pool = memory_db().await;
    let user_id = crate::auth::setup_admin(&pool, "admin", "password123").await.unwrap();
    let key = SoftKey::generate();
    let cred_id = b"cred-id-16-bytes".to_vec();
    let challenge = "reg-challenge";

    let ok_auth = auth_data(RP_ID, UP | UV | AT, 9, Some((&cred_id, &key.cose)), &[]);
    let resp = registration(&cred_id, &cred_id, &ok_auth, challenge, ORIGIN, "webauthn.create", None);
    verify_and_store_credential(&pool, user_id, &resp, challenge, &rp(), true)
        .await
        .unwrap();
    let creds = stored(&pool, user_id).await;
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].credential_id, cred_id);
    assert_eq!(creds[0].public_key, key.cose);
    assert_eq!(creds[0].sign_count, 9);
    assert_eq!(creds[0].origin.as_deref(), Some(ORIGIN));
    assert_eq!(creds[0].rp_id.as_deref(), Some(RP_ID));
    assert!(creds[0].created_at.contains('T'));

    let ed_id = b"cred-id-with-ed!!".to_vec();
    let ext = extension_map();
    let ed_auth = auth_data(RP_ID, UP | UV | AT | ED, 4, Some((&ed_id, &key.cose)), &ext);
    let resp = registration(&ed_id, &ed_id, &ed_auth, challenge, ORIGIN, "webauthn.create", None);
    verify_and_store_credential(&pool, user_id, &resp, challenge, &rp(), true)
        .await
        .unwrap();
    let creds = stored(&pool, user_id).await;
    let ed = creds.iter().find(|c| c.credential_id == ed_id).unwrap();
    assert_eq!(ed.public_key, key.cose);

    let cases: Vec<(&str, RegistrationResponse)> = vec![
        (
            "authData 格式错误",
            registration(
                b"trail-cred-id!!!!",
                b"trail-cred-id!!!!",
                &auth_data(RP_ID, UP | UV | AT, 1, Some((b"trail-cred-id!!!!", &key.cose)), &[0x00]),
                challenge,
                ORIGIN,
                "webauthn.create",
                None,
            ),
        ),
        (
            "rpIdHash 不匹配",
            registration(
                b"bad-rpid-cred!!!!",
                b"bad-rpid-cred!!!!",
                &auth_data("wrong.example", UP | UV | AT, 1, Some((b"bad-rpid-cred!!!!", &key.cose)), &[]),
                challenge,
                ORIGIN,
                "webauthn.create",
                None,
            ),
        ),
        (
            "需要用户验证",
            registration(
                b"no-uv-cred-id!!!!",
                b"no-uv-cred-id!!!!",
                &auth_data(RP_ID, UP | AT, 1, Some((b"no-uv-cred-id!!!!", &key.cose)), &[]),
                challenge,
                ORIGIN,
                "webauthn.create",
                None,
            ),
        ),
        (
            "origin 不匹配",
            registration(
                b"bad-origin-cred!!",
                b"bad-origin-cred!!",
                &auth_data(RP_ID, UP | UV | AT, 1, Some((b"bad-origin-cred!!", &key.cose)), &[]),
                challenge,
                "https://other.example",
                "webauthn.create",
                None,
            ),
        ),
        (
            "challenge 不匹配",
            registration(
                b"bad-chal-cred-id!",
                b"bad-chal-cred-id!",
                &auth_data(RP_ID, UP | UV | AT, 1, Some((b"bad-chal-cred-id!", &key.cose)), &[]),
                "other-challenge",
                ORIGIN,
                "webauthn.create",
                None,
            ),
        ),
        (
            "无效的 clientData type",
            registration(
                b"bad-type-cred-id!",
                b"bad-type-cred-id!",
                &auth_data(RP_ID, UP | UV | AT, 1, Some((b"bad-type-cred-id!", &key.cose)), &[]),
                challenge,
                ORIGIN,
                "webauthn.get",
                None,
            ),
        ),
        (
            "不支持跨域嵌入",
            registration(
                b"cross-origin-cred",
                b"cross-origin-cred",
                &auth_data(RP_ID, UP | UV | AT, 1, Some((b"cross-origin-cred", &key.cose)), &[]),
                challenge,
                ORIGIN,
                "webauthn.create",
                Some(r#""crossOrigin":true"#),
            ),
        ),
        (
            "authData 标志位无效",
            registration(
                b"bs-without-be!!!!",
                b"bs-without-be!!!!",
                &auth_data(RP_ID, UP | UV | AT | BS, 1, Some((b"bs-without-be!!!!", &key.cose)), &[]),
                challenge,
                ORIGIN,
                "webauthn.create",
                None,
            ),
        ),
    ];
    for (needle, resp) in cases {
        let before = stored(&pool, user_id).await.len();
        let err = verify_and_store_credential(&pool, user_id, &resp, challenge, &rp(), true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(needle), "want {needle} in {err}");
        assert_eq!(stored(&pool, user_id).await.len(), before);
    }

    let bad_alg = {
        let pt = key.signing.verifying_key().to_encoded_point(false);
        cose_key(&pt.x().unwrap()[..], &pt.y().unwrap()[..], 2, -257)
    };
    let bad_kty = {
        let pt = key.signing.verifying_key().to_encoded_point(false);
        cose_key(&pt.x().unwrap()[..], &pt.y().unwrap()[..], 1, -7)
    };
    for (id, cose) in [("alg-not-es256!!!!", bad_alg), ("kty-not-ec2!!!!!", bad_kty)] {
        let id = id.as_bytes();
        let resp = registration(
            id,
            id,
            &auth_data(RP_ID, UP | UV | AT, 1, Some((id, &cose)), &[]),
            challenge,
            ORIGIN,
            "webauthn.create",
            None,
        );
        let err = verify_and_store_credential(&pool, user_id, &resp, challenge, &rp(), true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("仅支持 ES256"), "{err}");
    }

    let mismatch_id = b"rawid-mismatch!!!".to_vec();
    let resp = registration(
        &mismatch_id,
        b"different-raw-id",
        &auth_data(RP_ID, UP | UV | AT, 1, Some((&mismatch_id, &key.cose)), &[]),
        challenge,
        ORIGIN,
        "webauthn.create",
        None,
    );
    let err = verify_and_store_credential(&pool, user_id, &resp, challenge, &rp(), true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("凭据 ID 不一致"), "{err}");

    let again = registration(&cred_id, &cred_id, &ok_auth, challenge, ORIGIN, "webauthn.create", None);
    let err = verify_and_store_credential(&pool, user_id, &again, challenge, &rp(), true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("该 Passkey 已注册"), "{err}");
}

#[tokio::test]
async fn authentication_cases() {
    let pool = memory_db().await;
    let user_id = crate::auth::setup_admin(&pool, "admin", "password123").await.unwrap();
    let key = SoftKey::generate();
    let cred_id = b"auth-cred-id-16b".to_vec();
    let challenge = "auth-challenge";
    let reg = registration(
        &cred_id,
        &cred_id,
        &auth_data(RP_ID, UP | UV | AT, 1, Some((&cred_id, &key.cose)), &[]),
        "reg-challenge",
        ORIGIN,
        "webauthn.create",
        None,
    );
    verify_and_store_credential(&pool, user_id, &reg, "reg-challenge", &rp(), true)
        .await
        .unwrap();

    let handle = b64(user_id.to_string().as_bytes());
    let ok = assertion(&key, &cred_id, RP_ID, UP | UV, 2, challenge, ORIGIN, Some(&handle), false);
    let got = verify_authentication(&pool, &ok, challenge).await.unwrap();
    assert_eq!(got, Some(user_id));
    assert_eq!(stored(&pool, user_id).await[0].sign_count, 2);

    let uv = assertion(&key, &cred_id, RP_ID, UP, 3, challenge, ORIGIN, Some(&handle), false);
    let err = verify_authentication(&pool, &uv, challenge).await.unwrap_err();
    assert!(err.to_string().contains("需要用户验证"), "{err}");

    let bad_rp = assertion(&key, &cred_id, "wrong.example", UP | UV, 3, challenge, ORIGIN, Some(&handle), false);
    let err = verify_authentication(&pool, &bad_rp, challenge).await.unwrap_err();
    assert!(err.to_string().contains("rpIdHash 不匹配"), "{err}");

    let bad_origin = assertion(
        &key,
        &cred_id,
        RP_ID,
        UP | UV,
        3,
        challenge,
        "https://pve.example.com:8443",
        Some(&handle),
        false,
    );
    let err = verify_authentication(&pool, &bad_origin, challenge).await.unwrap_err();
    assert!(err.to_string().contains("该 Passkey 绑定于"), "{err}");
    assert!(err.to_string().contains(ORIGIN), "{err}");

    let missing = assertion(&key, &cred_id, RP_ID, UP | UV, 3, challenge, ORIGIN, None, false);
    let err = verify_authentication(&pool, &missing, challenge).await.unwrap_err();
    assert!(err.to_string().contains("Passkey 用户标识不匹配"), "{err}");

    let wrong = assertion(&key, &cred_id, RP_ID, UP | UV, 3, challenge, ORIGIN, Some(&b64(b"999")), false);
    let err = verify_authentication(&pool, &wrong, challenge).await.unwrap_err();
    assert!(err.to_string().contains("Passkey 用户标识不匹配"), "{err}");

    let bad_sig = assertion(&key, &cred_id, RP_ID, UP | UV, 3, challenge, ORIGIN, Some(&handle), true);
    let err = verify_authentication(&pool, &bad_sig, challenge).await.unwrap_err();
    assert!(err.to_string().contains("签名"), "{err}");

    set_count(&pool, user_id, 5).await;
    for new_count in [0u32, 5] {
        let resp = assertion(&key, &cred_id, RP_ID, UP | UV, new_count, challenge, ORIGIN, Some(&handle), false);
        let err = verify_authentication(&pool, &resp, challenge).await.unwrap_err();
        assert!(err.to_string().contains("sign_count 回退"), "{err} count={new_count}");
        assert_eq!(stored(&pool, user_id).await[0].sign_count, 5);
    }

    set_count(&pool, user_id, 0).await;
    let zero = assertion(&key, &cred_id, RP_ID, UP | UV, 0, challenge, ORIGIN, Some(&handle), false);
    assert_eq!(verify_authentication(&pool, &zero, challenge).await.unwrap(), Some(user_id));

    let legacy_id = b"legacy-cred-id!!".to_vec();
    let legacy = json!([{
        "credential_id": legacy_id,
        "public_key": key.cose,
        "sign_count": 0,
        "created_at": "2020-01-01T00:00:00Z"
    }]);
    let legacy_json = legacy.to_string();
    assert!(!crate::passkey::has_usable_credential(&legacy_json));
    sqlx::query("UPDATE users SET passkey_credential = ? WHERE id = ?")
        .bind(&legacy_json)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let legacy_assert = assertion(&key, &legacy_id, RP_ID, UP | UV, 1, challenge, ORIGIN, Some(&handle), false);
    assert!(verify_authentication(&pool, &legacy_assert, challenge).await.is_err());
}

async fn set_count(pool: &SqlitePool, user_id: i64, count: u32) {
    let mut creds = stored(pool, user_id).await;
    creds[0].sign_count = count;
    let json = serde_json::to_string(&creds).unwrap();
    sqlx::query("UPDATE users SET passkey_credential = ? WHERE id = ?")
        .bind(&json)
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
}

struct HttpResp {
    status: u16,
    cookie: Option<String>,
    body: Value,
}

fn set_cookie_session(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get("set-cookie")?.to_str().ok()?;
    let part = raw.split(';').next()?;
    let (name, value) = part.split_once('=')?;
    (name == "session").then(|| value.to_string())
}

async fn test_app() -> (axum::Router, SqlitePool) {
    let pool = memory_db().await;
    let state = Arc::new(crate::AppState {
        db: pool.clone(),
        master_key: vec![0u8; 32],
        tls_enabled: false,
        login_limiter: crate::ratelimit::RateLimiter::new(5, 300),
        static_dir: "static".into(),
        known_hosts_path: "data/known_hosts".into(),
        job_locks: crate::jobs::HostLocks::default(),
    });
    (crate::api::routes(state), pool)
}

async fn call(app: &axum::Router, method: &str, path: &str, body: &str, cookie: Option<&str>) -> HttpResp {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("origin", ORIGIN);
    if let Some(c) = cookie {
        builder = builder.header("cookie", format!("session={c}"));
    }
    let mut req = builder.body(Body::from(body.to_string())).unwrap();
    req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 3210))));
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let cookie = set_cookie_session(resp.headers());
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    HttpResp { status, cookie, body }
}

async fn sessions(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions").fetch_one(pool).await.unwrap()
}

fn assert_err(resp: &HttpResp, msg: &str) {
    assert_eq!(resp.status, StatusCode::OK.as_u16(), "{}", resp.body);
    assert_eq!(resp.body["ok"], false, "{}", resp.body);
    assert_eq!(resp.body["error"], msg, "{}", resp.body);
}

#[tokio::test]
async fn router_mfa_flows() {
    let (app, pool) = test_app().await;
    let pw = "password123";

    let setup = call(&app, "POST", "/auth/setup", r#"{"username":"admin","password":"password123"}"#, None).await;
    assert_eq!(setup.body["ok"], true, "{}", setup.body);
    assert_eq!(setup.body["needs_enrollment"], true, "{}", setup.body);
    assert_eq!(setup.body["message"], "账户已创建，请绑定二次验证");
    let c_setup = setup.cookie.expect("setup cookie");
    assert_eq!(call(&app, "GET", "/results/stats", "", Some(&c_setup)).await.status, 401);

    let login_new = call(&app, "POST", "/auth/login", r#"{"username":"admin","password":"password123"}"#, None).await;
    assert_eq!(login_new.body["needs_mfa"], false, "{}", login_new.body);
    assert_eq!(login_new.body["needs_enrollment"], true, "{}", login_new.body);
    assert!(login_new.cookie.is_some());

    let before = sessions(&pool).await;
    let bad = call(&app, "POST", "/auth/login", r#"{"username":"admin","password":"wrong-password"}"#, None).await;
    assert_err(&bad, "用户名或密码错误");
    assert!(bad.cookie.is_none());
    assert_eq!(sessions(&pool).await, before);

    let start = call(&app, "POST", "/passkey/register/start", "", Some(&c_setup)).await;
    assert_eq!(start.body["ok"], true, "{}", start.body);
    assert_eq!(start.body["rp"]["id"], RP_ID);
    let challenge = start.body["challenge"].as_str().unwrap().to_string();
    let user_id: i64 = start.body["user"]["id"].as_str().unwrap().parse().unwrap();
    let key = SoftKey::generate();
    let cred_id = b"router-cred-id!!".to_vec();
    let reg_auth = auth_data(RP_ID, UP | UV | AT, 0, Some((&cred_id, &key.cose)), &[]);
    let reg = registration(&cred_id, &cred_id, &reg_auth, &challenge, ORIGIN, "webauthn.create", None);
    let finish = call(
        &app,
        "POST",
        "/passkey/register/finish",
        &serde_json::to_string(&json!({
            "id": b64(&cred_id),
            "rawId": b64(&cred_id),
            "type": "public-key",
            "response": {
                "attestationObject": reg.response.attestation_object,
                "clientDataJSON": reg.response.client_data_json,
            }
        }))
        .unwrap(),
        Some(&c_setup),
    )
    .await;
    assert_eq!(finish.body["ok"], true, "{}", finish.body);
    assert_eq!(finish.body["message"], "Passkey 注册成功");
    assert_eq!(call(&app, "GET", "/results/stats", "", Some(&c_setup)).await.status, 200);

    let login_start = call(&app, "POST", "/passkey/login/start", r#"{"username":"admin"}"#, None).await;
    assert_eq!(login_start.body["ok"], true, "{}", login_start.body);
    assert_eq!(login_start.body["rpId"], RP_ID);
    let auth_challenge = login_start.body["challenge"].as_str().unwrap().to_string();
    let handle = b64(user_id.to_string().as_bytes());
    let auth_resp = assertion_json(&key, &cred_id, RP_ID, UP | UV, 1, &auth_challenge, ORIGIN, Some(&handle), false);
    let login_finish = call(
        &app,
        "POST",
        "/passkey/login/finish",
        &serde_json::to_string(&json!({"credential": auth_resp})).unwrap(),
        None,
    )
    .await;
    assert_eq!(login_finish.body["ok"], true, "{}", login_finish.body);
    let c_pk = login_finish.cookie.expect("passkey cookie");
    assert_ne!(c_pk, c_setup);
    assert_eq!(call(&app, "GET", "/results/stats", "", Some(&c_pk)).await.status, 200);

    let del = call(&app, "POST", "/passkey/delete", "", Some(&c_pk)).await;
    assert_err(&del, "Passkey 是当前唯一的登录验证方式，请先绑定 TOTP 再删除");

    let before = sessions(&pool).await;
    let pw_only = call(&app, "POST", "/auth/login", r#"{"username":"admin","password":"password123"}"#, None).await;
    assert_err(&pw_only, "用户名或密码错误");
    assert!(pw_only.cookie.is_none());
    assert_eq!(sessions(&pool).await, before);

    let wrong_pw = call(&app, "POST", "/auth/totp/setup", r#"{"password":"nope1234"}"#, Some(&c_pk)).await;
    assert_err(&wrong_pw, "密码错误");
    let totp = call(
        &app,
        "POST",
        "/auth/totp/setup",
        &format!(r#"{{"password":"{pw}"}}"#),
        Some(&c_pk),
    )
    .await;
    assert_eq!(totp.body["ok"], true, "{}", totp.body);
    let active = totp.body["totp_secret"].as_str().unwrap().to_string();
    let confirm = call(
        &app,
        "POST",
        "/auth/totp/confirm",
        &format!(r#"{{"code":"{}"}}"#, crate::totp::current_code(&active)),
        Some(&c_pk),
    )
    .await;
    assert_eq!(confirm.body["ok"], true, "{}", confirm.body);
    assert_eq!(confirm.body["message"], "TOTP 已绑定");
    assert_eq!(call(&app, "GET", "/results/stats", "", Some(&c_pk)).await.status, 200);

    let mfa = call(&app, "POST", "/auth/login", r#"{"username":"admin","password":"password123"}"#, None).await;
    assert_eq!(mfa.body["needs_mfa"], true, "{}", mfa.body);
    assert_eq!(mfa.body["needs_enrollment"], false, "{}", mfa.body);
    assert_eq!(mfa.body["message"], "需要二次验证");
    let c_partial = mfa.cookie.expect("partial cookie");
    for (path, body) in [
        ("/passkey/register/start", ""),
        ("/passkey/register/finish", "{}"),
        ("/auth/totp/setup", r#"{"password":"password123"}"#),
    ] {
        let resp = call(&app, "POST", path, body, Some(&c_partial)).await;
        assert_err(&resp, "请先完成二次验证");
    }
    assert_eq!(call(&app, "GET", "/results/stats", "", Some(&c_partial)).await.status, 401);

    let pending_resp = call(
        &app,
        "POST",
        "/auth/totp/setup",
        &format!(r#"{{"password":"{pw}"}}"#),
        Some(&c_pk),
    )
    .await;
    assert_eq!(pending_resp.body["ok"], true, "{}", pending_resp.body);
    let pending = pending_resp.body["totp_secret"].as_str().unwrap().to_string();
    assert_ne!(pending, active);
    let still_active: String = sqlx::query_scalar("SELECT totp_secret FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(still_active, active);

    let partial2 = call(&app, "POST", "/auth/login", r#"{"username":"admin","password":"password123"}"#, None).await;
    let c2 = partial2.cookie.expect("second partial");
    let rejected = call(
        &app,
        "POST",
        "/auth/verify-totp",
        &format!(r#"{{"code":"{}"}}"#, crate::totp::current_code(&pending)),
        Some(&c2),
    )
    .await;
    assert_eq!(rejected.body["ok"], false, "{}", rejected.body);
    let accepted = call(
        &app,
        "POST",
        "/auth/verify-totp",
        &format!(r#"{{"code":"{}"}}"#, crate::totp::current_code(&active)),
        Some(&c2),
    )
    .await;
    assert_eq!(accepted.body["ok"], true, "{}", accepted.body);

    let disabled = call(
        &app,
        "POST",
        "/auth/disable-totp",
        &format!(r#"{{"password":"{pw}"}}"#),
        Some(&c_pk),
    )
    .await;
    assert_eq!(disabled.body["ok"], true, "{}", disabled.body);
    assert_eq!(disabled.body["message"], "TOTP 已禁用");
    let row: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT totp_secret, totp_pending_secret FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(row.0.is_none());
    assert!(row.1.is_none());
    let del_after = call(&app, "POST", "/passkey/delete", "", Some(&c_pk)).await;
    assert_err(&del_after, "Passkey 是当前唯一的登录验证方式，请先绑定 TOTP 再删除");

    let totp_again = call(
        &app,
        "POST",
        "/auth/totp/setup",
        &format!(r#"{{"password":"{pw}"}}"#),
        Some(&c_pk),
    )
    .await;
    let active2 = totp_again.body["totp_secret"].as_str().unwrap().to_string();
    let confirm2 = call(
        &app,
        "POST",
        "/auth/totp/confirm",
        &format!(r#"{{"code":"{}"}}"#, crate::totp::current_code(&active2)),
        Some(&c_pk),
    )
    .await;
    assert_eq!(confirm2.body["ok"], true, "{}", confirm2.body);
    let removed = call(&app, "POST", "/passkey/delete", "", Some(&c_pk)).await;
    assert_eq!(removed.body["ok"], true, "{}", removed.body);
    let totp_only = call(
        &app,
        "POST",
        "/auth/disable-totp",
        &format!(r#"{{"password":"{pw}"}}"#),
        Some(&c_pk),
    )
    .await;
    assert_err(&totp_only, "TOTP 是当前唯一的登录验证方式，请先注册 Passkey 再禁用");

    let totp_login = call(&app, "POST", "/auth/login", r#"{"username":"admin","password":"password123"}"#, None).await;
    assert_eq!(totp_login.body["needs_mfa"], true, "{}", totp_login.body);
    assert_eq!(totp_login.body["needs_enrollment"], false, "{}", totp_login.body);

    let reset = call(&app, "POST", "/auth/reset-totp", r#"{"password":"password123"}"#, Some(&c_pk)).await;
    assert_eq!(reset.status, 404);
}

#[tokio::test]
async fn stale_enrollment_updates() {
    let pool = memory_db().await;
    let user_id = crate::auth::setup_admin(&pool, "admin", "password123").await.unwrap();

    sqlx::query("UPDATE users SET totp_secret = 'ABC' WHERE id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let wrote = crate::passkey::store_credential_if_eligible(&pool, user_id, false, None, "[]")
        .await
        .unwrap();
    assert!(!wrote);
    let still: Option<String> = sqlx::query_scalar("SELECT passkey_credential FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(still.is_none());

    sqlx::query("UPDATE users SET totp_secret = NULL, passkey_credential = '[]' WHERE id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let wrote = crate::passkey::store_credential_if_eligible(&pool, user_id, true, Some("stale"), "[1]")
        .await
        .unwrap();
    assert!(!wrote);
    let cur: String = sqlx::query_scalar("SELECT passkey_credential FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cur, "[]");

    let key = SoftKey::generate();
    let usable = serde_json::to_string(&vec![StoredCredential {
        credential_id: b"usable-cred".to_vec(),
        public_key: key.cose.clone(),
        sign_count: 1,
        created_at: "2020-01-01T00:00:00Z".into(),
        origin: Some(ORIGIN.into()),
        rp_id: Some(RP_ID.into()),
    }])
    .unwrap();
    assert!(crate::passkey::has_usable_credential(&usable));
    sqlx::query("UPDATE users SET totp_pending_secret = 'PEND', totp_secret = NULL, passkey_credential = ? WHERE id = ?")
        .bind(&usable)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let promoted = crate::auth::promote_pending_totp(&pool, user_id, false, "PEND", None)
        .await
        .unwrap();
    assert!(!promoted);
    let totp: Option<String> = sqlx::query_scalar("SELECT totp_secret FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(totp.is_none());
    let pend: Option<String> = sqlx::query_scalar("SELECT totp_pending_secret FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pend.as_deref(), Some("PEND"));

    sqlx::query("UPDATE users SET passkey_credential = NULL WHERE id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let promoted = crate::auth::promote_pending_totp(&pool, user_id, false, "OTHER", None)
        .await
        .unwrap();
    assert!(!promoted);
    let pend: String = sqlx::query_scalar("SELECT totp_pending_secret FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pend, "PEND");
}
