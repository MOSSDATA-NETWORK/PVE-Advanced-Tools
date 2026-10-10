use axum::{extract::{Path, State}, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::{AppState, db};

#[derive(Deserialize)]
pub struct ScanVmRequest {
    pub vmid: String,
}

pub async fn list(State(state): State<Arc<AppState>>) -> Json<Value> {
    match db::list_hosts(&state.db).await {
        Ok(hosts) => {
            let public: Vec<_> = hosts.iter().map(|h| h.to_public()).collect();
            Json(json!({"ok": true, "data": public}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn get(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    match db::get_host(&state.db, id).await {
        Ok(host) => Json(json!({"ok": true, "data": host.to_public()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 主机组件安装状态（host_components ��细，主机详情页用）
pub async fn components(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let rows = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "SELECT component, status, detail, updated_at FROM host_components WHERE host_id=? ORDER BY component"
    ).bind(id).fetch_all(&state.db).await;
    match rows {
        Ok(r) => Json(json!({"ok": true, "data": r.iter().map(|(c, st, d, t)| json!({
            "component": c, "status": st, "detail": d, "updated_at": t
        })).collect::<Vec<_>>()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 添加主机：保存凭据后抓取 SSH 主机密钥指纹，待用户确认后才允许部署与执行任务
pub async fn create(State(state): State<Arc<AppState>>, jar: CookieJar, Json(body): Json<db::CreateHost>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    let host = match db::create_host(&state.db, body, &state.master_key).await {
        Ok(h) => h,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };

    crate::audit::log(&state.db, &actor, "host.create", Some("host"), Some(host.id),
        Some(&format!("{} ({}:{})", host.name, host.host, host.port)), None).await;

    // 抓取主机密钥指纹（TOFU：首次接入需用户确认）
    match crate::hostkey::scan(&host.host, host.port as u16).await {
        Ok((line, fingerprint)) => {
            let _ = sqlx::query("UPDATE hosts SET host_key_fingerprint=?, host_key_known_hosts=?, host_key_status='pending' WHERE id=?")
                .bind(&fingerprint).bind(&line).bind(host.id)
                .execute(&state.db).await;
            let host = db::get_host(&state.db, host.id).await.unwrap_or(host);
            Json(json!({
                "ok": true,
                "data": host.to_public(),
                "message": "主机已添加。请核对并确认 SSH 指纹后再部署组件",
            }))
        }
        Err(e) => Json(json!({
            "ok": true,
            "data": host.to_public(),
            "warning": format!("主机已添加，但指纹抓取失败（可稍后重试）: {}", e),
        })),
    }
}

pub async fn update(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>, Json(body): Json<db::UpdateHost>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    // 地址/端口变更后原指纹失效，需要重新确认
    let addr_changed = body.host.is_some() || body.port.is_some();
    match db::update_host(&state.db, id, body, &state.master_key).await {
        Ok(host) => {
            if addr_changed {
                let _ = sqlx::query("UPDATE hosts SET host_key_status='pending' WHERE id=?")
                    .bind(id).execute(&state.db).await;
                let _ = crate::hostkey::write_known_hosts(&state.db, &state.known_hosts_path).await;
            }
            crate::audit::log(&state.db, &actor, "host.update", Some("host"), Some(id), None, None).await;
            Json(json!({"ok": true, "data": host.to_public()}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn delete(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    let name = db::get_host(&state.db, id).await.map(|h| h.name).unwrap_or_default();
    match db::delete_host(&state.db, id).await {
        Ok(_) => {
            crate::audit::log(&state.db, &actor, "host.delete", Some("host"), Some(id),
                Some(&name), None).await;
            let _ = crate::hostkey::write_known_hosts(&state.db, &state.known_hosts_path).await;
            Json(json!({"ok": true}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// 抓取/刷新主机 SSH 指纹（地址变更或首次接入失败时重试）
pub async fn hostkey_scan(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let host = match db::get_host(&state.db, id).await {
        Ok(h) => h,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    match crate::hostkey::scan(&host.host, host.port as u16).await {
        Ok((line, fingerprint)) => {
            // 已确认指纹与新抓取不一致 → 提示可能的中间人风险，需重新确认
            let changed = host.host_key_fingerprint.as_deref().map(|old| old != fingerprint).unwrap_or(false);
            let _ = sqlx::query("UPDATE hosts SET host_key_fingerprint=?, host_key_known_hosts=?, host_key_status='pending' WHERE id=?")
                .bind(&fingerprint).bind(&line).bind(id)
                .execute(&state.db).await;
            let _ = crate::hostkey::write_known_hosts(&state.db, &state.known_hosts_path).await;
            Json(json!({
                "ok": true,
                "data": {"fingerprint": fingerprint, "changed": changed},
                "warning": if changed { Some("指纹与已确认值不一致，请确认主机未被替换或劫持") } else { None::<&str> },
            }))
        }
        Err(e) => Json(json!({"ok": false, "error": format!("指纹抓取失败: {}", e)})),
    }
}

#[derive(Deserialize)]
pub struct HostkeyConfirmRequest {
    /// 用户在弹窗中核对过的指纹：条件确认，防并发重扫替换（TOCTOU）
    pub fingerprint: String,
}

/// 确认主机指纹：请求必须携带用户已核对的指纹，条件更新；随后自动部署检测脚本并探测能力
pub async fn hostkey_confirm(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>, Json(body): Json<HostkeyConfirmRequest>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    let host = match db::get_host(&state.db, id).await {
        Ok(h) => h,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    if host.host_key_fingerprint.is_none() {
        return Json(json!({"ok": false, "error": "尚未抓取指纹，请先执行指纹扫描"}));
    }

    // 条件确认：只有当前库中指纹与用户核对值一致才生效
    let r = match sqlx::query("UPDATE hosts SET host_key_status='confirmed' WHERE id=? AND host_key_fingerprint=?")
        .bind(id).bind(&body.fingerprint).execute(&state.db).await {
        Ok(r) => r,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    if r.rows_affected() == 0 {
        return Json(json!({"ok": false, "error": "指纹已变化（可能被重新扫描），请重新核对后再确认"}));
    }
    // 写入失败时回退为 pending，不留「已确认但 known_hosts 缺失」状态
    if let Err(e) = crate::hostkey::write_known_hosts(&state.db, &state.known_hosts_path).await {
        let _ = sqlx::query("UPDATE hosts SET host_key_status='pending' WHERE id=?")
            .bind(id).execute(&state.db).await;
        return Json(json!({"ok": false, "error": format!("known_hosts 写入失败，状态已回退为待确认: {}", e)}));
    }
    crate::audit::log(&state.db, &actor, "host.hostkey_confirm", Some("host"), Some(id),
        host.host_key_fingerprint.as_deref(), None).await;

    // 自动部署检测脚本（指纹固定连接）
    let auth = match make_ssh_auth(&host, &state.master_key) {
        Ok(a) => a,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    let kh = Some(state.known_hosts_path.as_str());
    let deploy_msg = match crate::deploy::deploy_script_kh(&host.host, host.port as u16, &host.username, &auth, kh).await {
        Ok(_) => {
            let _ = db::update_host_agent_status(&state.db, id, true).await;
            let _ = db::update_host_status(&state.db, id, "online").await;
            "，检测脚本已部署".to_string()
        }
        Err(e) => format!("，但脚本部署失败: {}", e),
    };

    // 能力探测（PVE 版本/架构）
    let probe_msg = match crate::probe::probe_capabilities(&state, id).await {
        Ok(caps) => format!("，PVE 主版本: {}", caps.pve_major.map(|v| v.to_string()).unwrap_or_else(|| "未识别".into())),
        Err(_) => String::new(),
    };

    Json(json!({"ok": true, "message": format!("指纹已确认{}{}", deploy_msg, probe_msg)}))
}

/// 手动触发能力探测
pub async fn probe(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    match crate::probe::probe_capabilities(&state, id).await {
        Ok(caps) => Json(json!({"ok": true, "data": caps})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn test_connection(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Json<Value> {
    let host = match db::get_host(&state.db, id).await {
        Ok(h) => h,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    if host.host_key_status.as_deref() != Some("confirmed") {
        return Json(json!({"ok": false, "error": "请先确认 SSH 主机指纹"}));
    }

    let auth = match make_ssh_auth(&host, &state.master_key) {
        Ok(a) => a,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    let kh = Some(state.known_hosts_path.as_str());
    match crate::deploy::deploy_script_kh(&host.host, host.port as u16, &host.username, &auth, kh).await {
        Ok(_) => {
            let _ = db::update_host_status(&state.db, id, "online").await;
            let _ = db::update_host_agent_status(&state.db, id, true).await;
            Json(json!({"ok": true, "message": "连接成功，检测脚本已部署"}))
        }
        Err(e) => {
            let _ = db::update_host_status(&state.db, id, "offline").await;
            Json(json!({"ok": false, "error": format!("连接失败: {}", e)}))
        }
    }
}

pub async fn deploy(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    let host = match db::get_host(&state.db, id).await {
        Ok(h) => h,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    if host.host_key_status.as_deref() != Some("confirmed") {
        return Json(json!({"ok": false, "error": "请先确认 SSH 主机指纹"}));
    }

    let auth = match make_ssh_auth(&host, &state.master_key) {
        Ok(a) => a,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    let kh = Some(state.known_hosts_path.as_str());
    match crate::deploy::deploy_script_kh(&host.host, host.port as u16, &host.username, &auth, kh).await {
        Ok(_) => {
            let _ = db::update_host_agent_status(&state.db, host.id, true).await;
            crate::audit::log(&state.db, &actor, "host.deploy_agent", Some("host"), Some(id), None, None).await;
            Json(json!({"ok": true, "message": "检测脚本已部署"}))
        }
        Err(e) => Json(json!({"ok": false, "error": format!("部署失败: {}", e)})),
    }
}

pub async fn scan_vm(State(state): State<Arc<AppState>>, jar: CookieJar, Path(id): Path<i64>, Json(body): Json<ScanVmRequest>) -> Json<Value> {
    let actor = crate::audit::actor_from_cookie(&state.db, &jar).await;
    // VMID 必须为纯数字（会拼入远程命令）
    if let Err(e) = crate::deploy::validate_vmid(&body.vmid) {
        return Json(json!({"ok": false, "error": e.to_string()}));
    }
    let host = match db::get_host(&state.db, id).await {
        Ok(h) => h,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };
    if host.host_key_status.as_deref() != Some("confirmed") {
        return Json(json!({"ok": false, "error": "请先确认 SSH 主机指纹"}));
    }

    let auth = match make_ssh_auth(&host, &state.master_key) {
        Ok(a) => a,
        Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
    };

    // 单 VM 磁盘扫描（指纹固定连接）；磁盘扫描独占 /dev/nbd，加主机锁防并发互踩
    let lock = state.job_locks.get(id);
    let _guard = lock.lock().await;
    match crate::deploy::run_remote_scan(&host.host, host.port as u16, &host.username, &auth, Some(&body.vmid), Some(&state.known_hosts_path)).await {
        Ok(output) => {
            // 解析结果并更新数据库
            tracing::info!("scan_vm {} raw output ({} bytes): {}", body.vmid, output.len(), output.chars().take(500).collect::<String>());
            match serde_json::from_str::<serde_json::Value>(&output) {
                Ok(result) => {
                    let empty = vec![];
                    let results = result.get("results").and_then(|r| r.as_array()).unwrap_or(&empty);
                    tracing::info!("scan_vm {} parsed {} results", body.vmid, results.len());
                    for r in results {
                        let vmid = r.get("vmid").and_then(|v| v.as_str()).unwrap_or("");
                        // 防串任务：远端返回的 vmid 必须与请求一致
                        if vmid != body.vmid {
                            tracing::warn!("scan_vm vmid 不匹配: 请求 {} 返回 {}，丢弃", body.vmid, vmid);
                            continue;
                        }
                        let status = r.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let method = r.get("method").and_then(|v| v.as_str()).unwrap_or("");
                        let evidence = r.get("evidence").and_then(|v| v.as_str()).unwrap_or("");

                        let db_status = if status == "detected" { "detected" }
                            else if status == "clean" { "clean" }
                            else if status == "needs_disk_scan" { "needs_disk_scan" }
                            else { "unknown" };

                        if let Err(e) = db::upsert_result(&state.db, 0, id, vmid, db_status, method, evidence).await {
                            tracing::error!("scan_vm upsert failed: {}", e);
                        }
                    }
                }
                Err(e) => tracing::error!("scan_vm {} parse failed: {}, raw: {}", body.vmid, e, output),
            }
            crate::audit::log(&state.db, &actor, "host.scan_vm", Some("host"), Some(id),
                Some(&format!("vmid={}", body.vmid)), None).await;
            Json(json!({"ok": true, "message": format!("VM {} 磁盘扫描完成", body.vmid)}))
        }
        Err(e) => Json(json!({"ok": false, "error": format!("扫描失败: {}", e)})),
    }
}

fn make_ssh_auth(host: &db::Host, master_key: &[u8]) -> anyhow::Result<crate::deploy::SshAuth> {
    crate::deploy::SshAuth::from_host(
        host.password_encrypted.as_deref(),
        host.ssh_key_encrypted.as_deref(),
        master_key,
    )
}
