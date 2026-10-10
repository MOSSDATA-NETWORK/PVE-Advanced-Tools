//! vmqos 节点面端点（契约 schema v2）：独立于管理员会话，按 token 鉴权。
//! 错误形状按契约 §5：{"error": {"code", "message", "retryable", "request_id"}}
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{qos, AppState};

fn err_body(code: &str, message: &str, retryable: bool) -> Value {
    json!({"error": {"code": code, "message": message, "retryable": retryable,
        "request_id": uuid::Uuid::new_v4().simple().to_string()}})
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers.get("authorization")?.to_str().ok()?.strip_prefix("Bearer ").map(str::trim)
}

fn x_api_token(headers: &HeaderMap) -> Option<&str> {
    headers.get("x-api-token").and_then(|v| v.to_str().ok()).map(str::trim)
}

/// token → 主机：校验用途、状态与指纹确认状态（未确认主机不提供 QoS 数据）
async fn host_by_token(state: &AppState, purpose: &str, token: &str) -> Option<crate::db::Host> {
    let host_id = qos::verify_token(&state.db, purpose, token).await?;
    let host = crate::db::get_host(&state.db, host_id).await.ok()?;
    if host.host_key_status.as_deref() != Some("confirmed") {
        return None;
    }
    Some(host)
}

#[derive(Deserialize)]
pub struct SnapshotQuery {
    node_ip: Option<String>,
}

/// GET /v1/vmqos/snapshot?node_ip= —— 契约 §2
pub async fn snapshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<SnapshotQuery>,
) -> (StatusCode, Json<Value>) {
    let Some(token) = bearer_token(&headers) else {
        return (StatusCode::UNAUTHORIZED, Json(err_body("UNAUTHORIZED", "缺少 Bearer token", false)));
    };
    let Some(host) = host_by_token(&state, "snapshot", token).await else {
        return (StatusCode::UNAUTHORIZED, Json(err_body("UNAUTHORIZED", "token 无效或主机未确认", false)));
    };
    let Some(node_ip) = q.node_ip else {
        return (StatusCode::BAD_REQUEST, Json(err_body("INVALID_REQUEST", "缺少 node_ip", false)));
    };
    // node_ip 必须与该 token 绑定主机的已确认管理地址一致（防 token 串用）
    if !qos::node_ip_matches(&host.host, &node_ip) {
        qos::record_node_error(&state.db, host.id, "node_ip 与管理地址不一致").await;
        return (StatusCode::FORBIDDEN, Json(err_body("NODE_FORBIDDEN", "node_ip 与主机不匹配", false)));
    }
    match qos::build_snapshot(&state, &host).await {
        Ok(snap) => {
            qos::record_snapshot_pull(&state.db, host.id, &snap).await;
            (StatusCode::OK, Json(snap))
        }
        Err(e) => {
            tracing::error!("快照生成失败 host={}: {}", host.id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(err_body("INTERNAL", "快照生成失败", true)))
        }
    }
}

#[derive(Deserialize)]
pub struct QosQuery {
    r: Option<String>,
    vmid: Option<String>,
    host_ip: Option<String>,
}

/// vmqos [qos].api_url 入口：POST ?r=api/report（事件上报），GET ?r=api/stage（档位核验）
pub async fn qos_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<QosQuery>,
    method: axum::http::Method,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    match (method.as_str(), q.r.as_deref()) {
        ("POST", Some("api/report")) => report(state, headers, body.map(|b| b.0)).await,
        ("GET", Some("api/stage")) => stage_query(state, headers, q).await,
        _ => (StatusCode::BAD_REQUEST, Json(err_body("INVALID_REQUEST", "未知请求（r 参数或方法不支持）", false))),
    }
}

async fn report(state: Arc<AppState>, headers: HeaderMap, body: Option<Value>) -> (StatusCode, Json<Value>) {
    let Some(token) = x_api_token(&headers) else {
        return (StatusCode::UNAUTHORIZED, Json(err_body("UNAUTHORIZED", "缺少 X-API-Token", false)));
    };
    let Some(host) = host_by_token(&state, "report", token).await else {
        return (StatusCode::UNAUTHORIZED, Json(err_body("UNAUTHORIZED", "token 无效或主机未确认", false)));
    };
    let Some(body) = body else {
        return (StatusCode::BAD_REQUEST, Json(err_body("INVALID_REQUEST", "缺少 JSON body", false)));
    };
    // vmid 按契约为字符串；limit_mbps 浮点；stage 整数
    let vmid = body.get("vmid").and_then(|v| v.as_str().map(String::from).or_else(|| v.as_u64().map(|n| n.to_string())));
    let stage = body.get("stage").and_then(|v| v.as_i64());
    let host_ip = body.get("host_ip").and_then(|v| v.as_str()).unwrap_or("");
    let (Some(vmid), Some(stage)) = (vmid, stage) else {
        return (StatusCode::BAD_REQUEST, Json(err_body("INVALID_REQUEST", "vmid/stage 缺失或类型错误", false)));
    };
    if vmid.parse::<u32>().is_err() || !(0..=255).contains(&stage) {
        return (StatusCode::BAD_REQUEST, Json(err_body("INVALID_REQUEST", "vmid/stage 取值非法", false)));
    }
    if !qos::node_ip_matches(&host.host, host_ip) {
        qos::record_node_error(&state.db, host.id, "report host_ip 与管理地址不一致").await;
        return (StatusCode::FORBIDDEN, Json(err_body("NODE_FORBIDDEN", "host_ip 与主机不匹配", false)));
    }
    // 非 0 档仅接受有启用策略的 VM（防 token 泄露后任意 VMID 刷事件）；
    // 0 档（删除）放行——策略刚被管理员移除时的在途删除上报仍需闭环
    if stage > 0 {
        // DB 错误不得当「无策略」吞掉（vmqos 会误以为已接受）：返回可重试 500
        let known = match sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM qos_policies WHERE host_id=? AND vmid=? AND origin='domestic' AND enabled=1"
        ).bind(host.id).bind(&vmid).fetch_one(&state.db).await {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("策略查询失败 host={}: {}", host.id, e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(err_body("INTERNAL", "查询失败", true)));
            }
        };
        if known == 0 {
            return (StatusCode::OK, Json(json!({"ok": true, "ignored": "no active policy"})));
        }
    }
    let limit = body.get("limit_mbps").and_then(|v| v.as_f64());
    match qos::record_event(&state, host.id, "domestic", &vmid, stage, limit).await {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))),
        Err(e) => {
            tracing::error!("QoS 事件写入失败 host={}: {}", host.id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(err_body("INTERNAL", "事件写入失败", true)))
        }
    }
}

/// 档位核验（契约：stage>0 需 200 {ok:true, stage}；stage=0/无记录需 404 或 {ok:false} 且 stage 空）
async fn stage_query(state: Arc<AppState>, headers: HeaderMap, q: QosQuery) -> (StatusCode, Json<Value>) {
    let Some(token) = x_api_token(&headers) else {
        return (StatusCode::UNAUTHORIZED, Json(err_body("UNAUTHORIZED", "缺少 X-API-Token", false)));
    };
    let Some(host) = host_by_token(&state, "report", token).await else {
        return (StatusCode::UNAUTHORIZED, Json(err_body("UNAUTHORIZED", "token 无效或主机未确认", false)));
    };
    let (Some(vmid), Some(host_ip)) = (q.vmid, q.host_ip) else {
        return (StatusCode::BAD_REQUEST, Json(err_body("INVALID_REQUEST", "缺少 vmid/host_ip", false)));
    };
    if !qos::node_ip_matches(&host.host, &host_ip) {
        return (StatusCode::FORBIDDEN, Json(err_body("NODE_FORBIDDEN", "host_ip 与主机不匹配", false)));
    }
    // DB 错误必须返回可重试 500——当作无记录会让 vmqos 误判「删除成功」
    let row = match sqlx::query_as::<_, (i64,)>(
        "SELECT current_stage FROM qos_vm_state WHERE host_id=? AND vmid=? AND origin='domestic'"
    )
    .bind(host.id).bind(&vmid).fetch_optional(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("stage 核验查询失败 host={}: {}", host.id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(err_body("INTERNAL", "查询失败", true)));
        }
    };
    match row {
        Some((stage,)) if stage > 0 => (StatusCode::OK, Json(json!({"ok": true, "stage": stage}))),
        _ => (StatusCode::NOT_FOUND, Json(json!({"ok": false, "stage": Value::Null}))),
    }
}

/// GET /v1/vmqos/agent/{version}/{file} —— vmqos 二进制代理下载。
/// 节点用快照 token 鉴权；平台带镜像 token 从 GitHub（可为私有仓库）拉取转发。
/// 未配置镜像 token 时 404（节点应直连公开仓库下载）。
pub async fn agent_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((version, file)): Path<(String, String)>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let unauthorized = || (StatusCode::UNAUTHORIZED, Json(err_body("UNAUTHORIZED", "token 无效", false))).into_response();
    let Some(token) = bearer_token(&headers) else { return unauthorized() };
    if qos::verify_token(&state.db, "snapshot", token).await.is_none() {
        return unauthorized();
    }
    // 严格白名单，防路径注入
    let ok = |x: &str| !x.is_empty() && x.len() <= 80
        && x.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c));
    if !ok(&version) || !ok(&file) || file.contains("..") {
        return (StatusCode::BAD_REQUEST, Json(err_body("INVALID_REQUEST", "参数非法", false))).into_response();
    }
    let Some(mirror) = qos::github_mirror_token(&state).await else {
        return (StatusCode::NOT_FOUND, Json(err_body("NOT_FOUND", "平台未配置镜像 token", false))).into_response();
    };
    // 私有仓库的 HTML 下载页不认 PAT——必须走 API：先按 tag 查 release 拿资产 ID，
    // 再按资产 ID 以 Accept: application/octet-stream 取内容
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        // reqwest 默认跨域重定向剥离 Authorization，S3 跳转不泄 token
        .redirect(reqwest::redirect::Policy::limited(5))
        .build().unwrap_or_default();
    let gh = |url: String, accept: &str| {
        client.get(url)
            .header("Authorization", format!("Bearer {}", mirror))
            .header("Accept", accept.to_string())
            .header("User-Agent", "pve-advanced-tools")
            .header("X-GitHub-Api-Version", "2022-11-28")
    };
    let bad_gateway = |msg: &str| (StatusCode::BAD_GATEWAY, Json(err_body("UPSTREAM", msg, true))).into_response();

    let rel_url = format!(
        "https://api.github.com/repos/MOSSDATA-NETWORK/vmqos/releases/tags/{}", version
    );
    let release = match gh(rel_url, "application/vnd.github+json").send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => return bad_gateway(&format!("GitHub 查询 release 返回 {}", r.status())),
        Err(e) => {
            tracing::error!("代理查询 release 失败: {}", e);
            return bad_gateway("连接 GitHub 失败");
        }
    };
    let body: Value = match release.json().await {
        Ok(v) => v,
        Err(_) => return bad_gateway("release 响应解析失败"),
    };
    let asset_id = body.get("assets").and_then(|a| a.as_array())
        .and_then(|arr| arr.iter().find(|a| a.get("name").and_then(|n| n.as_str()) == Some(&file)))
        .and_then(|a| a.get("id")).and_then(|i| i.as_u64());
    let Some(asset_id) = asset_id else {
        return (StatusCode::NOT_FOUND, Json(err_body("NOT_FOUND", "发布中无此文件", false))).into_response();
    };

    let dl_url = format!("https://api.github.com/repos/MOSSDATA-NETWORK/vmqos/releases/assets/{}", asset_id);
    match gh(dl_url, "application/octet-stream").send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.bytes().await {
                Ok(bytes) => (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    bytes,
                ).into_response(),
                Err(_) => bad_gateway("读取上游内容失败"),
            }
        }
        Ok(resp) => bad_gateway(&format!("GitHub 下载返回 {}", resp.status())),
        Err(e) => {
            tracing::error!("代理下载失败: {}", e);
            bad_gateway("连接 GitHub 失败")
        }
    }
}

#[derive(Deserialize)]
pub struct IntlQuery {
    cluster_id: Option<i64>,
    vmid: Option<String>,
}

/// 国际站端点（[international_qos].api_url 完整 URL，不拼接 ?r=）：
/// POST 上报 {cluster_id, vmid, stage, host_ip, limit_mbps?}；GET ?cluster_id&vmid 核验 {ok, active, stage}
pub async fn intl_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<IntlQuery>,
    method: axum::http::Method,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    // X-API-Token 与 Bearer 同时携带同一 token（vmqos 行为），任取其一校验
    let token = x_api_token(&headers).or_else(|| bearer_token(&headers));
    let Some(token) = token else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "error": "缺少 token"})));
    };
    let Some(host) = host_by_token(&state, "intl", token).await else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "error": "token 无效或主机未确认"})));
    };

    if method.as_str() == "POST" {
        let Some(body) = body.map(|b| b.0) else {
            return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "缺少 JSON body"})));
        };
        let vmid = body.get("vmid").and_then(|v| v.as_u64().map(|n| n.to_string()).or_else(|| v.as_str().map(String::from)));
        let stage = body.get("stage").and_then(|v| v.as_i64());
        let host_ip = body.get("host_ip").and_then(|v| v.as_str()).unwrap_or("");
        let (Some(vmid), Some(stage)) = (vmid, stage) else {
            return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "vmid/stage 缺失"})));
        };
        if vmid.parse::<u32>().is_err() || !(0..=255).contains(&stage) {
            return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "vmid/stage 取值非法"})));
        }
        if !qos::node_ip_matches(&host.host, host_ip) {
            qos::record_node_error(&state.db, host.id, "intl report host_ip 不一致").await;
            return (StatusCode::FORBIDDEN, Json(json!({"ok": false, "error": "host_ip 与主机不匹配"})));
        }
        // cluster_id 须与主机集群一致；非 0 档须有启用的国际源策略
        let host_cluster = match sqlx::query_scalar::<_, i64>("SELECT COALESCE(cluster_id, 1) FROM hosts WHERE id=?")
            .bind(host.id).fetch_one(&state.db).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("集群查询失败 host={}: {}", host.id, e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": "查询失败，请重试"})));
            }
        };
        // cluster_id 必须显式携带且与主机集群一致（缺失/类型错/不符一律拒绝）
        match body.get("cluster_id").and_then(|v| v.as_i64()) {
            Some(c) if c == host_cluster => {}
            _ => return (StatusCode::FORBIDDEN, Json(json!({"ok": false, "error": "cluster_id 缺失或与主机集群不匹配"}))),
        }
        if stage > 0 {
            let known = match sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM qos_policies WHERE host_id=? AND vmid=? AND origin='international' AND enabled=1"
            ).bind(host.id).bind(&vmid).fetch_one(&state.db).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!("intl 策略查询失败 host={}: {}", host.id, e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": "查询失败，请重试"})));
                }
            };
            if known == 0 {
                return (StatusCode::OK, Json(json!({"ok": true, "ignored": "no active policy"})));
            }
        }
        let limit = body.get("limit_mbps").and_then(|v| v.as_f64());
        return match qos::record_event(&state, host.id, "international", &vmid, stage, limit).await {
            Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))),
            Err(e) => {
                tracing::error!("intl QoS 事件写入失败 host={}: {}", host.id, e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": "事件写入失败"})))
            }
        };
    }

    // GET 核验：0 档要求 active:false；非零要求 active:true 且 stage 一致
    let Some(vmid) = q.vmid else {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "缺少 vmid"})));
    };
    // cluster_id 须与主机所属集群一致（防 token 跨集群查询）
    let host_cluster = match sqlx::query_scalar::<_, i64>("SELECT COALESCE(cluster_id, 1) FROM hosts WHERE id=?")
        .bind(host.id).fetch_one(&state.db).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("集群查询失败 host={}: {}", host.id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": "查询失败，请重试"})));
        }
    };
    if q.cluster_id.map(|c| c != host_cluster).unwrap_or(true) {
        return (StatusCode::FORBIDDEN, Json(json!({"ok": false, "error": "cluster_id 缺失或与主机集群不匹配"})));
    }
    let row = match sqlx::query_as::<_, (i64,)>(
        "SELECT current_stage FROM qos_vm_state WHERE host_id=? AND vmid=? AND origin='international'"
    )
    .bind(host.id).bind(&vmid).fetch_optional(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("intl 核验查询失败 host={}: {}", host.id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": "查询失败，请重试"})));
        }
    };
    let stage = row.map(|r| r.0).unwrap_or(0);
    (StatusCode::OK, Json(json!({"ok": true, "active": stage > 0, "stage": stage})))
}
