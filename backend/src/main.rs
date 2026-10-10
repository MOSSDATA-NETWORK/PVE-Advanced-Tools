mod api;
mod alerts;
mod audit;
mod auth;
mod crypto;
mod db;
mod deploy;
mod detect;
mod hostkey;
mod jobs;
mod notify;
mod passkey;
mod probe;
mod qos;
mod ratelimit;
mod scheduler;
mod tasks;
mod totp;
mod version;
mod vms;

use axum::Router;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower_http::cors::{CorsLayer, AllowOrigin, AllowMethods, AllowHeaders};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub master_key: Vec<u8>,
    pub tls_enabled: bool,
    pub login_limiter: ratelimit::RateLimiter,
    pub static_dir: String,
    pub index_html: String,
    /// 平台维护的 known_hosts 文件路径（指纹固定后 SSH 必用）
    pub known_hosts_path: String,
    /// 每主机任务串行锁
    pub job_locks: jobs::HostLocks,
}

/// 迁移器：按名称记录已应用的迁移，避免重复执行（ALTER 不具备幂等性）
async fn run_migrations(pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        .execute(pool)
        .await?;

    let migrations: [(&str, &str); 5] = [
        ("001_init", include_str!("../migrations/001_init.sql")),
        ("002_p0", include_str!("../migrations/002_p0.sql")),
        ("003_p1", include_str!("../migrations/003_p1.sql")),
        ("004_p4", include_str!("../migrations/004_p4.sql")),
        ("005_p3", include_str!("../migrations/005_p3.sql")),
    ];

    for (name, sql) in migrations {
        let applied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _migrations WHERE name = ?)")
            .bind(name)
            .fetch_one(pool)
            .await?;
        if applied {
            continue;
        }
        // 先剥离 -- 注释行（注释中可能含分号），再逐语句执行；
        // ALTER 列已存在（老库升级中途失败重跑）时容忍
        let stripped: String = sql
            .lines()
            .filter(|l| !l.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        for stmt in stripped.split(';') {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            if let Err(e) = sqlx::query(stmt).execute(pool).await {
                let msg = e.to_string();
                if msg.contains("duplicate column name") {
                    continue;
                }
                return Err(anyhow::anyhow!("迁移 {} 失败: {}", name, msg));
            }
        }
        sqlx::query("INSERT INTO _migrations (name) VALUES (?)")
            .bind(name)
            .execute(pool)
            .await?;
        tracing::info!("数据库迁移 {} 已应用", name);
    }

    // 结构性补丁：job_steps 的 CHECK 约束无法通过 ALTER 追加，
    // 老库（002 早期版本）缺约束时重建表
    let table_sql: Option<String> = sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE name='job_steps'")
        .fetch_optional(pool)
        .await?;
    if let Some(sql) = table_sql {
        if !sql.contains("CHECK") {
            tracing::info!("重建 job_steps 表以补充 CHECK 约束");
            // 单事务重建：DROP 后中断也不会留下缺表状态
            let rebuild = [
                "CREATE TABLE job_steps_new (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE, seq INTEGER NOT NULL, name TEXT NOT NULL, command TEXT NOT NULL, rollback_command TEXT, rerun_safe INTEGER NOT NULL DEFAULT 1 CHECK (rerun_safe IN (0,1)), status TEXT NOT NULL DEFAULT 'pending', output TEXT, exit_code INTEGER, started_at DATETIME, finished_at DATETIME, UNIQUE(job_id, seq))",
                "INSERT INTO job_steps_new SELECT * FROM job_steps",
                "DROP TABLE job_steps",
                "ALTER TABLE job_steps_new RENAME TO job_steps",
            ];
            let mut tx = pool.begin().await?;
            for stmt in rebuild {
                sqlx::query(stmt).execute(&mut *tx).await?;
            }
            tx.commit().await?;
        }
    }
    // 结构性补丁（幂等）：老库补建 P4 的 trigger_type 唯一索引。
    // 单事务：先去重（历史告警的 rule_id 重映射到保留项）再建索引，失败整体回滚
    if sqlx::query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_rules'")
        .fetch_optional(pool).await?.is_some()
    {
        let mut tx = pool.begin().await?;
        sqlx::query(
            "UPDATE alert_history SET rule_id = (SELECT MIN(r2.id) FROM alert_rules r2 WHERE r2.trigger_type = \
             (SELECT trigger_type FROM alert_rules WHERE id = alert_history.rule_id)) \
             WHERE rule_id IN (SELECT id FROM alert_rules WHERE id NOT IN (SELECT MIN(id) FROM alert_rules GROUP BY trigger_type))"
        ).execute(&mut *tx).await?;
        sqlx::query(
            "DELETE FROM alert_rules WHERE id NOT IN (SELECT MIN(id) FROM alert_rules GROUP BY trigger_type)"
        ).execute(&mut *tx).await?;
        sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_rules_trigger ON alert_rules(trigger_type)")
            .execute(&mut *tx).await?;
        tx.commit().await?;
    }

    // 结构性补丁（幂等）：results 去重 + (host_id, vmid) 唯一索引（并发扫描防重复行）
    if sqlx::query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='results'")
        .fetch_optional(pool).await?.is_some()
    {
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM results WHERE id NOT IN (SELECT MAX(id) FROM results GROUP BY host_id, vmid)")
            .execute(&mut *tx).await?;
        sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_results_host_vm ON results(host_id, vmid)")
            .execute(&mut *tx).await?;
        tx.commit().await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:pve-advanced-tools.db?mode=rwc".to_string());

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // 运行数据库迁移
    run_migrations(&pool).await?;

    // 更新自检：迁移通过后清除更新标记（失败时进程已退出，可用 .bak 回滚）
    version::confirm_update_marker().await;

    // 内置管控模板种子（SMTP/BT 端口、默认拦截域名）
    seed_builtin(&pool).await;

    // 加密密钥：优先从环境变量读取，否则自动生成并打印
    let master_key = load_or_generate_master_key();

    // 检查 TLS 配置
    let tls_cert = std::env::var("TLS_CERT").ok();
    let tls_key = std::env::var("TLS_KEY").ok();
    // TLS 启用条件：直接配置了证书，或位于 TLS 反代之后
    let behind_tls_proxy = std::env::var("BEHIND_TLS_PROXY").map(|v| v == "1" || v == "true").unwrap_or(false);
    let tls_enabled = (tls_cert.is_some() && tls_key.is_some()) || behind_tls_proxy;

    let static_dir = std::env::var("STATIC_DIR")
        .unwrap_or_else(|_| "static".to_string());

    let index_html = std::fs::read_to_string(format!("{}/index.html", static_dir))
        .unwrap_or_else(|_| "<h1>index.html not found</h1>".to_string());

    // 平台数据目录：known_hosts 等运行时文件
    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string());
    let known_hosts_path = format!("{}/known_hosts", data_dir);

    let state = Arc::new(AppState {
        db: pool.clone(),
        master_key,
        tls_enabled,
        login_limiter: ratelimit::RateLimiter::new(5, 300), // 5次/5分钟
        static_dir: static_dir.clone(),
        index_html,
        known_hosts_path: known_hosts_path.clone(),
        job_locks: jobs::HostLocks::default(),
    });

    // 启动时重建 known_hosts（所有已确认指纹的主机）
    match hostkey::write_known_hosts(&state.db, &state.known_hosts_path).await {
        Ok(n) => tracing::info!("known_hosts 已重建（{} 台已确认主机）", n),
        Err(e) => tracing::warn!("known_hosts 重建失败: {}", e),
    }

    // 平台重启对账：中断的 running 任务标记失败，queued 任务重新入队
    match jobs::reconcile_on_boot(&state.db).await {
        Ok(queued) => {
            for job_id in &queued {
                tracing::info!("重启后恢复任务 {}", job_id);
                jobs::resume_background(state.clone(), *job_id);
            }
        }
        Err(e) => tracing::warn!("任务对账失败: {}", e),
    }

    // 启动定时任务调度器
    let scheduler_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = scheduler::start(scheduler_state).await {
            tracing::error!("Scheduler error: {}", e);
        }
    });

    // 启动时自动检查并重新部署检测脚本（版本不一致时）
    let deploy_state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        if let Err(e) = deploy::redeploy_all(&deploy_state.db, &deploy_state.master_key, &deploy_state.known_hosts_path).await {
            tracing::warn!("Script auto-redeploy: {}", e);
        }
    });

    // 定期清理过期 session
    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
            auth::cleanup_sessions(&cleanup_pool).await;
        }
    });

    let port = std::env::var("PORT").unwrap_or_else(|_| "3210".to_string());
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

    // CORS：只允许同源
    let origin_str = if tls_enabled { "https" } else { "http" };
    let default_origin = format!("{}://{}:{}", origin_str, host, port);
    let cors_origin = std::env::var("CORS_ORIGIN").unwrap_or(default_origin);
    let origin: axum::http::HeaderValue = cors_origin.parse()
        .map_err(|e| anyhow::anyhow!("CORS_ORIGIN 格式错误: {}", e))?;

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(origin))
        .allow_methods(AllowMethods::list([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ]))
        .allow_headers(AllowHeaders::list([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::COOKIE,
        ]))
        .allow_credentials(true);

    let app = Router::new()
        .nest("/api", api::routes(state.clone()))
        .fallback_service(tower::service_fn(move |req: axum::http::Request<axum::body::Body>| {
            let static_dir = state.static_dir.clone();
            let index_html = state.index_html.clone();
            async move {
                let path = req.uri().path().to_string();

                // 安全检查：拒绝路径穿越和空字节
                if path.contains("..") || path.contains('\0') {
                    return Ok::<_, std::convert::Infallible>(
                        axum::response::Response::builder()
                            .status(400)
                            .body(axum::body::Body::from("Bad Request"))
                            .unwrap()
                    );
                }

                // 规范化路径，确认在 static_dir 内
                let file_path = std::path::Path::new(&static_dir).join(path.trim_start_matches('/'));
                let canonical = match tokio::fs::canonicalize(&file_path).await {
                    Ok(p) => p,
                    Err(_) => {
                        // 文件不存在，返回 index.html（SPA 路由）
                        // index.html 禁止缓存：引用带哈希的资产名，缓存旧版会导致白屏
                        return Ok(axum::response::Response::builder()
                            .header("content-type", "text/html; charset=utf-8")
                            .header("cache-control", "no-cache, no-store, must-revalidate")
                            .body(axum::body::Body::from(index_html))
                            .unwrap());
                    }
                };

                // 确认 canonical 路径仍在 static_dir 内
                let static_canonical = tokio::fs::canonicalize(&static_dir).await
                    .unwrap_or_else(|_| std::path::PathBuf::from(&static_dir));
                if !canonical.starts_with(&static_canonical) {
                    return Ok::<_, std::convert::Infallible>(
                        axum::response::Response::builder()
                            .status(403)
                            .body(axum::body::Body::from("Forbidden"))
                            .unwrap()
                    );
                }

                // 尝试返回静态文件
                if canonical.is_file() {
                    if let Ok(content) = tokio::fs::read(&canonical).await {
                        let mime = mime_guess::from_path(&canonical)
                            .first_or_octet_stream()
                            .to_string();
                        // 带 hash 的 assets 永久缓存；其他文件与 index.html 相同策略禁缓存
                        let is_hashed_asset = path.starts_with("/assets/");
                        let cache = if is_hashed_asset {
                            "public, max-age=31536000, immutable"
                        } else {
                            "no-cache, no-store, must-revalidate"
                        };
                        return Ok(axum::response::Response::builder()
                            .header("content-type", mime)
                            .header("cache-control", cache)
                            .body(axum::body::Body::from(content))
                            .unwrap());
                    }
                }

                // 非文件返回 index.html
                Ok(axum::response::Response::builder()
                    .header("content-type", "text/html; charset=utf-8")
                    .header("cache-control", "no-cache, no-store, must-revalidate")
                    .body(axum::body::Body::from(index_html))
                    .unwrap())
            }
        }))
        .layer(cors);

    let addr: std::net::SocketAddr = format!("{}:{}", host, port).parse()?;

    if let (Some(cert_path), Some(key_path)) = (&tls_cert, &tls_key) {
        tracing::info!("PVE-Advanced-Tools v{} running on https://{}:{} (TLS enabled)", version::VERSION, host, port);
        let tls_config = load_tls_config(cert_path, key_path).await?;
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        tracing::warn!("PVE-Advanced-Tools v{} running on http://{}:{} (无 TLS，建议配置 HTTPS)", version::VERSION, host, port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    }

    Ok(())
}

/// 加载或生成加密密钥
fn load_or_generate_master_key() -> Vec<u8> {
    if let Ok(key_hex) = std::env::var("MASTER_KEY") {
        // 从环境变量加载
        match hex_to_bytes(&key_hex) {
            Ok(key) if key.len() == 32 => {
                tracing::info!("已从环境变量加载加密密钥");
                return key;
            }
            _ => {
                tracing::error!("MASTER_KEY 环境变量格式错误，需要64位hex字符（32字节）");
                std::process::exit(1);
            }
        }
    }

    // 自动生成并打印
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let hex = bytes_to_hex(&key);

    eprintln!("");
    eprintln!("╔══════════════════════════════════════════════════╗");
    eprintln!("║           加密密钥已自动生成                      ║");
    eprintln!("╠══════════════════════════════════════════════════╣");
    eprintln!("║ MASTER_KEY={}", hex);
    eprintln!("║");
    eprintln!("║ 请保存此密钥！后续启动必须设置此环境变量。");
    eprintln!("║ 丢失密钥将无法解密已存储的凭据。");
    eprintln!("╚══════════════════════════════════════════════════╝");
    eprintln!("");

    key.to_vec()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> anyhow::Result<Vec<u8>> {
    if hex.len() % 2 != 0 || hex.len() != 64 {
        return Err(anyhow::anyhow!("长度错误"));
    }
    Ok((0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?)
}

async fn load_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| anyhow::anyhow!("TLS 配置失败: {}", e))?;
    Ok(config)
}

/// 内置模板种子：SMTP/BT 端口封堵与默认拦截域名（幂等）
async fn seed_builtin(pool: &sqlx::SqlitePool) {
    let _ = sqlx::query(
        "INSERT OR IGNORE INTO netguard_ports (id, name, ports, enabled, builtin) VALUES (1, 'SMTP/BT 模板', '25,26,465,587,6880:6999', 1, 1)"
    ).execute(pool).await;
    for d in ["shlii.io", "userlocations.googleapis.com"] {
        let _ = sqlx::query("INSERT OR IGNORE INTO netguard_domains (domain, comment) VALUES (?, '内置')")
            .bind(d).execute(pool).await;
    }
    // 默认告警规则（幂等）
    let rules: [(&str, &str, Option<i64>); 4] = [
        ("节点离线/巡检失败", "host_offline", None),
        ("任务执行失败", "job_failed", None),
        ("资源水位过高", "resource_high", Some(90)),
        ("管控组件失效", "inspect_failed", None),
    ];
    for (name, trigger, threshold) in rules {
        let _ = sqlx::query(
            "INSERT INTO alert_rules (name, trigger_type, threshold) \
             SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM alert_rules WHERE trigger_type = ?)"
        )
        .bind(name).bind(trigger).bind(threshold).bind(trigger)
        .execute(pool).await;
    }
    // 内置 QoS 档位模板（与 vmqos 默认 [stages] 一致，幂等）
    let _ = sqlx::query(
        "INSERT INTO qos_templates (name, config_json, builtin) \
         SELECT '默认阶梯', ?, 1 WHERE NOT EXISTS (SELECT 1 FROM qos_templates WHERE builtin = 1)"
    )
    .bind(crate::qos::builtin_template().to_string())
    .execute(pool).await;
}
