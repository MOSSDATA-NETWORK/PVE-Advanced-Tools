//! 任务包构建器：把平台组件动作翻译成 SSH 作业器任务（JobSpec）
//! 约定：
//! - 脚本上传走 base64 单步原子落盘（写 .tmp 再 mv），幂等、可安全重跑
//! - netguard（管控类）= fail_closed；arpfilter（ARP 降噪类）= fail_open（不断网优先）
//! - 组件安装状态在任务成功后由 post_job_hook 回写 host_components
use base64::Engine;
use serde_json::json;
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::jobs::{JobSpec, StepSpec, POLICY_FAIL_CLOSED, POLICY_FAIL_OPEN};
use crate::AppState;

const NETGUARD_SCRIPT: &str = include_str!("../scripts/vm-netguard.sh");
const ARPFILTER_PASSIVE: &str = include_str!("../scripts/pve-arpfilter.py");
const ARPFILTER_STATIC: &str = include_str!("../scripts/pve-arpfilter-static.py");

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// 单步原子上传脚本命令（写 .tmp 再 mv，幂等可重跑）
fn upload_cmd(content: &str, dest: &str) -> String {
    format!(
        "echo '{}' | base64 -d > {}.tmp && chmod 755 {}.tmp && mv {}.tmp {}",
        b64(content), dest, dest, dest, dest
    )
}

fn step(name: &str, command: String, rollback: Option<String>) -> StepSpec {
    StepSpec {
        name: name.to_string(),
        command,
        rollback_command: rollback,
        rerun_safe: true,
    }
}

// ==================== netguard ====================

/// 从 DB 组装一台主机的 /etc/vm-netguard.conf 内容
async fn netguard_conf(pool: &SqlitePool, host_id: i64) -> anyhow::Result<String> {
    let log_enabled = get_setting(pool, "netguard_log_enabled").await
        .map(|v| v == "1" || v == "true").unwrap_or(false);
    let ports: Vec<(String,)> = sqlx::query_as("SELECT ports FROM netguard_ports WHERE enabled = 1 ORDER BY id")
        .fetch_all(pool).await?;
    let domains: Vec<(String,)> = sqlx::query_as("SELECT domain FROM netguard_domains WHERE enabled = 1 ORDER BY id")
        .fetch_all(pool).await?;
    let whitelist: Vec<(i64,)> = sqlx::query_as("SELECT vmid FROM netguard_whitelist WHERE host_id = ? ORDER BY vmid")
        .bind(host_id).fetch_all(pool).await?;

    let drop_ports = ports.iter().map(|p| p.0.as_str()).collect::<Vec<_>>().join(",");
    // iptables multiport 单规则最多 15 个元素（合并所有启用条目后校验）
    let total_elems = ports.iter().map(|p| p.0.split(',').filter(|x| !x.is_empty()).count()).sum::<usize>();
    if total_elems > 15 {
        return Err(anyhow::anyhow!(
            "启用的端口条目合并后共 {} 个元素，超过 iptables multiport 单规则 15 个上限，请停用部分条目", total_elems
        ));
    }
    let block_domains = domains.iter().map(|d| d.0.as_str()).collect::<Vec<_>>().join(" ");
    let wl = whitelist.iter().map(|w| w.0.to_string()).collect::<Vec<_>>().join(" ");

    Ok(format!(
        "# 由 PVE-Advanced-Tools 平台生成，请勿手工编辑\nBLOCK_DOMAINS=\"{}\"\nDROP_PORTS=\"{}\"\nWHITELIST_VMIDS=\"{}\"\nENABLE_LOG=\"{}\"\n",
        block_domains, drop_ports, wl, if log_enabled { "1" } else { "0" }
    ))
}

fn netguard_precheck() -> StepSpec {
    step("环境预检", r#"command -v iptables >/dev/null && command -v ip6tables >/dev/null || { echo '缺少 iptables'; exit 1; }
if systemctl is-active pve-firewall >/dev/null 2>&1; then echo '警告: PVE 防火墙运行中，请确认规则不冲突'; fi
echo '预检通过'"#.to_string(), None)
}

/// netguard 安装任务（上传脚本 + 写配置 + install）
pub async fn netguard_install(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<JobSpec> {
    let conf = netguard_conf(&state.db, host_id).await?;
    Ok(JobSpec {
        kind: "netguard.install".into(),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 120,
        queue_ttl_secs: 1800,
        steps: vec![
            netguard_precheck(),
            StepSpec {
                name: "上传 vm-netguard 脚本".into(),
                command: upload_cmd(NETGUARD_SCRIPT, "/usr/local/sbin/vm-netguard.sh"),
                rollback_command: Some("rm -f /usr/local/sbin/vm-netguard.sh".into()),
                rerun_safe: true,
            },
            StepSpec {
                name: "下发管控配置".into(),
                command: format!("echo '{}' | base64 -d > /etc/vm-netguard.conf.tmp && mv /etc/vm-netguard.conf.tmp /etc/vm-netguard.conf", b64(&conf)),
                rollback_command: Some("rm -f /etc/vm-netguard.conf".into()),
                rerun_safe: true,
            },
            step("安装并应用", "/usr/local/sbin/vm-netguard.sh install".into(),
                Some("/usr/local/sbin/vm-netguard.sh uninstall".into())),
        ],
    })
}

/// netguard 配置变更任务（备份旧配置 + 下发 + apply；失败回滚到上一版本配置并重载）
pub async fn netguard_apply(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<JobSpec> {
    let conf = netguard_conf(&state.db, host_id).await?;
    Ok(JobSpec {
        kind: "netguard.apply".into(),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 120,
        queue_ttl_secs: 1800,
        steps: vec![
            step("备份当前配置",
                "cp -a /etc/vm-netguard.conf /etc/vm-netguard.conf.bak".into(),
                None),
            StepSpec {
                name: "下发管控配置".into(),
                command: format!("echo '{}' | base64 -d > /etc/vm-netguard.conf.tmp && mv /etc/vm-netguard.conf.tmp /etc/vm-netguard.conf", b64(&conf)),
                rollback_command: Some("cp -a /etc/vm-netguard.conf.bak /etc/vm-netguard.conf".into()),
                rerun_safe: true,
            },
            // apply 失败 → 回滚 = 恢复旧配置并按旧配置重建规则（回到上一可用版本）
            step("应用规则", "/usr/local/sbin/vm-netguard.sh apply".into(),
                Some("cp -a /etc/vm-netguard.conf.bak /etc/vm-netguard.conf && /usr/local/sbin/vm-netguard.sh apply".into())),
        ],
    })
}

pub fn netguard_uninstall() -> JobSpec {
    JobSpec {
        kind: "netguard.uninstall".into(),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 120,
        queue_ttl_secs: 1800,
        steps: vec![step("卸载 netguard", "/usr/local/sbin/vm-netguard.sh uninstall".into(), None)],
    }
}

/// 拉取节点拦截日志（需 ENABLE_LOG=1 并重新下发配置后产生记录）
pub fn netguard_logs() -> JobSpec {
    JobSpec {
        kind: "netguard.logs".into(),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 60,
        queue_ttl_secs: 600,
        steps: vec![step("读取拦截日志", "/usr/local/sbin/vm-netguard.sh logs".into(), None)],
    }
}

/// ARP 效果统计回采（输出 ARPSTATS:{json} 行，post_job_hook 解析入 arp_stats）
pub fn arpfilter_stats(mode: &str) -> JobSpec {
    let dest = if mode == "static" { "/usr/local/sbin/pve-arpfilter-static.py" } else { "/usr/local/sbin/pve-arpfilter.py" };
    JobSpec {
        kind: "arpfilter.stats".into(),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 60,
        queue_ttl_secs: 600,
        steps: vec![step("采集丢弃计数", format!("{} stats", dest), None)],
    }
}

/// 切鸡特征库下发（/etc/chicken-signatures.conf，chicken-check.sh 运行时读取）
pub async fn detect_push_signatures(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<JobSpec> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT sig_type, value, name FROM detect_signatures WHERE enabled = 1 ORDER BY id"
    ).fetch_all(&state.db).await?;
    // 字符白名单在脚本侧还有一道；这里先拦掉明显非法的
    let mut lines = String::from("# 由 PVE-Advanced-Tools 平台下发，请勿手工编辑\n");
    for (t, v, n) in &rows {
        let ok = |x: &str| !x.is_empty() && x.chars().all(|c| c.is_ascii_alphanumeric() || ".-_/~:".contains(c));
        if ok(v) && ok(n) {
            lines.push_str(&format!("{}|{}|{}\n", t, v, n));
        }
    }
    Ok(JobSpec {
        kind: "detect.signatures".into(),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 60,
        queue_ttl_secs: 600,
        steps: vec![step("下发特征库",
            format!("echo '{}' | base64 -d > /etc/chicken-signatures.conf.tmp && chmod 644 /etc/chicken-signatures.conf.tmp && mv /etc/chicken-signatures.conf.tmp /etc/chicken-signatures.conf", b64(&lines)),
            None)],
    })
}

pub fn netguard_status() -> JobSpec {
    JobSpec {
        kind: "netguard.status".into(),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 60,
        queue_ttl_secs: 600,
        steps: vec![step("读取状态", "/usr/local/sbin/vm-netguard.sh status".into(), None)],
    }
}

// ==================== arpfilter ====================

/// arpfilter 安装任务（mode = passive / static）
pub async fn arpfilter_install(state: &Arc<AppState>, host_id: i64, mode: &str) -> anyhow::Result<JobSpec> {
    let (script, dest, unit) = match mode {
        "passive" => (ARPFILTER_PASSIVE, "/usr/local/sbin/pve-arpfilter.py", "pve-arpfilter"),
        "static" => (ARPFILTER_STATIC, "/usr/local/sbin/pve-arpfilter-static.py", "pve-arpfilter-static"),
        _ => return Err(anyhow::anyhow!("模式必须为 passive 或 static")),
    };

    let mut steps = vec![
        step("环境预检", r#"command -v nft >/dev/null && command -v python3 >/dev/null || { echo '缺少 nft 或 python3'; exit 1; }
if [ "$1" = "passive" ]; then command -v tcpdump >/dev/null || { echo '缺少 tcpdump（被动学习模式需要）'; exit 1; }; fi
echo '预检通过'"#.replace("$1", mode), None),
        StepSpec {
            name: format!("上传 {} 脚本", mode),
            command: upload_cmd(script, dest),
            rollback_command: Some(format!("rm -f {}", dest)),
            rerun_safe: true,
        },
    ];

    // static 模式：先下发映射文件与灰度白名单再启动
    if mode == "static" {
        steps.push(StepSpec {
            name: "下发映射与白名单".into(),
            command: arp_files_cmd(state, host_id).await?,
            rollback_command: None,
            rerun_safe: true,
        });
    } else {
        steps.push(StepSpec {
            name: "下发灰度白名单".into(),
            command: arp_whitelist_cmd(state, host_id).await?,
            rollback_command: None,
            rerun_safe: true,
        });
    }

    steps.push(step(
        "安装并启动",
        format!("{} install", dest),
        Some(format!("{} uninstall", dest)),
    ));

    let _ = unit;
    Ok(JobSpec {
        kind: format!("arpfilter.install.{}", mode),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 180,
        queue_ttl_secs: 1800,
        steps,
    })
}

pub fn arpfilter_uninstall(mode: &str) -> JobSpec {
    let dest = if mode == "static" { "/usr/local/sbin/pve-arpfilter-static.py" } else { "/usr/local/sbin/pve-arpfilter.py" };
    JobSpec {
        kind: format!("arpfilter.uninstall.{}", mode),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 120,
        queue_ttl_secs: 1800,
        steps: vec![step("卸载 arpfilter", format!("{} uninstall", dest), None)],
    }
}

/// arpfilter 模式切换：单任务内先卸旧再装新（避免两个任务竞争主机锁导致顺序不确定）
pub async fn arpfilter_switch(state: &Arc<AppState>, host_id: i64, old_mode: &str, new_mode: &str) -> anyhow::Result<JobSpec> {
    let old_dest = if old_mode == "static" { "/usr/local/sbin/pve-arpfilter-static.py" } else { "/usr/local/sbin/pve-arpfilter.py" };
    let mut install = arpfilter_install(state, host_id, new_mode).await?;
    let mut steps = vec![step(
        &format!("卸载 {} 模式", old_mode),
        format!("{} uninstall", old_dest),
        None,
    )];
    steps.append(&mut install.steps);
    Ok(JobSpec {
        kind: format!("arpfilter.switch.{}.{}", old_mode, new_mode),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 300,
        queue_ttl_secs: 1800,
        steps,
    })
}

/// arpfilter 数据同步任务（白名单 + static 映射文件 + 触发一次调和）
pub async fn arpfilter_sync(state: &Arc<AppState>, host_id: i64, mode: &str) -> anyhow::Result<JobSpec> {
    let mut steps = vec![];
    if mode == "static" {
        steps.push(StepSpec {
            name: "下发映射文件".into(),
            command: arp_files_cmd(state, host_id).await?,
            rollback_command: None,
            rerun_safe: true,
        });
    }
    steps.push(StepSpec {
        name: "下发灰度白名单".into(),
        command: arp_whitelist_cmd(state, host_id).await?,
        rollback_command: None,
        rerun_safe: true,
    });
    let dest = if mode == "static" { "/usr/local/sbin/pve-arpfilter-static.py" } else { "/usr/local/sbin/pve-arpfilter.py" };
    let unit = if mode == "static" { "pve-arpfilter-static" } else { "pve-arpfilter" };
    // 守护进程每轮 reconcile 自动重读白名单/映射：在跑就只需重启立即生效；
    // 没在跑才用 once（acquire_lock 与 daemon 互斥，直接 once 会撞锁 traceback）
    steps.push(step("下发并生效",
        format!("systemctl is-active --quiet {u} && systemctl restart {u} || {d} once", u = unit, d = dest),
        None));
    Ok(JobSpec {
        kind: format!("arpfilter.sync.{}", mode),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 180,
        queue_ttl_secs: 1800,
        steps,
    })
}

pub fn arpfilter_status(mode: &str) -> JobSpec {
    let dest = if mode == "static" { "/usr/local/sbin/pve-arpfilter-static.py" } else { "/usr/local/sbin/pve-arpfilter.py" };
    JobSpec {
        kind: "arpfilter.status".into(),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 60,
        queue_ttl_secs: 600,
        steps: vec![step("读取状态", format!("{} status", dest), None)],
    }
}

/// 生成白名单文件写入命令（空名单 = 删除文件，脚本语义为全量过滤）
async fn arp_whitelist_cmd(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<String> {
    let rows: Vec<(i64,)> = sqlx::query_as("SELECT vmid FROM arp_whitelist WHERE host_id = ? ORDER BY vmid")
        .bind(host_id).fetch_all(&state.db).await?;
    if rows.is_empty() {
        return Ok("rm -f /etc/pve/arpfilter.whitelist".into());
    }
    let content = rows.iter().map(|r| r.0.to_string()).collect::<Vec<_>>().join("\n") + "\n";
    Ok(format!(
        "echo '{}' | base64 -d > /etc/pve/arpfilter.whitelist.tmp && mv /etc/pve/arpfilter.whitelist.tmp /etc/pve/arpfilter.whitelist",
        b64(&content)
    ))
}

/// 生成 static 模式映射文件写入命令（先清旧映射再写，缺映射的 VM fail-open 不装规则）
async fn arp_files_cmd(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<String> {
    let rows: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT vmid, nic, ip FROM arp_maps WHERE host_id = ? ORDER BY vmid, nic, ip"
    )
    .bind(host_id).fetch_all(&state.db).await?;

    let mut files: std::collections::BTreeMap<(i64, i64), Vec<String>> = Default::default();
    for (vmid, nic, ip) in rows {
        files.entry((vmid, nic)).or_default().push(ip);
    }

    let mut cmd = String::from("mkdir -p /etc/pve/arpfilter && rm -f /etc/pve/arpfilter/*.ips");
    for ((vmid, nic), ips) in files {
        let content = ips.join("\n") + "\n";
        cmd.push_str(&format!(
            " && echo '{}' | base64 -d > /etc/pve/arpfilter/{}.{}.ips.tmp && mv /etc/pve/arpfilter/{}.{}.ips.tmp /etc/pve/arpfilter/{}.{}.ips",
            b64(&content), vmid, nic, vmid, nic, vmid, nic
        ));
    }
    Ok(cmd)
}

// ==================== 组件状态回写 ====================

/// 任务成功后回写组件状态（在 jobs.rs 成功路径调用）
pub async fn post_job_hook(state: &Arc<AppState>, job: &crate::jobs::Job) -> anyhow::Result<()> {
    // ARP 统计回采：解析 ARPSTATS 行入库（只留最近 200 条/主机）
    if job.kind == "arpfilter.stats" {
        let out: Option<String> = sqlx::query_scalar(
            "SELECT output FROM job_steps WHERE job_id=? AND output LIKE '%ARPSTATS:%' ORDER BY seq DESC LIMIT 1"
        ).bind(job.id).fetch_optional(&state.db).await?;
        if let Some(out) = out {
            if let Some(line) = out.lines().find(|l| l.starts_with("ARPSTATS:")) {
                let payload = &line["ARPSTATS:".len()..];
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                    if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                        let vm = v.get("vm_drops").cloned().unwrap_or(json!({})).to_string();
                        let bpdu = v.get("bpdu_drops").and_then(|x| x.as_i64()).unwrap_or(0);
                        sqlx::query("INSERT INTO arp_stats (host_id, vm_drops, bpdu_drops) VALUES (?, ?, ?)")
                            .bind(job.host_id).bind(vm).bind(bpdu).execute(&state.db).await?;
                        sqlx::query("DELETE FROM arp_stats WHERE host_id=? AND id NOT IN (SELECT id FROM arp_stats WHERE host_id=? ORDER BY id DESC LIMIT 200)")
                            .bind(job.host_id).bind(job.host_id).execute(&state.db).await?;
                    }
                }
            }
        }
    }

    let (component, installed) = match job.kind.as_str() {
        "netguard.install" | "netguard.apply" => ("netguard", true),
        "netguard.uninstall" => ("netguard", false),
        "qos.install" | "qos.config_apply" => ("vmqos", true),
        "qos.uninstall" => ("vmqos", false),
        "optimize.init" => ("nosub", true),
        "optimize.tune" => ("optimize", true),
        "optimize.rollback.nosub" => ("nosub", false),
        "optimize.rollback.optimize" => ("optimize", false),
        k if k.starts_with("arpfilter.install.") || k.starts_with("arpfilter.switch.") => ("arpfilter", true),
        k if k.starts_with("arpfilter.uninstall.") => ("arpfilter", false),
        _ => return Ok(()),
    };

    let r = if installed {
        sqlx::query(
            "INSERT INTO host_components (host_id, component, status, detail, updated_at) VALUES (?, ?, 'installed', ?, CURRENT_TIMESTAMP) \
             ON CONFLICT(host_id, component) DO UPDATE SET status='installed', detail=excluded.detail, updated_at=CURRENT_TIMESTAMP"
        )
        .bind(job.host_id).bind(component).bind(&job.kind)
        .execute(&state.db).await
    } else {
        sqlx::query("DELETE FROM host_components WHERE host_id=? AND component=?")
            .bind(job.host_id).bind(component)
            .execute(&state.db).await
    };
    // 回写失败向上传播：由调用方在任务上标注异常（任务本体已成功，不回滚远端状态）
    if let Err(e) = r {
        return Err(anyhow::anyhow!("组件状态回写失败 host={} {}: {}", job.host_id, component, e));
    }

    // arpfilter 安装/切换/卸载同步 arp_mode 表（失败向上传播，由调用方标注任务）
    if let Some(mode) = job.kind.strip_prefix("arpfilter.install.") {
        sqlx::query(
            "INSERT INTO arp_mode (host_id, mode, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) \
             ON CONFLICT(host_id) DO UPDATE SET mode=excluded.mode, updated_at=CURRENT_TIMESTAMP"
        )
        .bind(job.host_id).bind(mode).execute(&state.db).await?;
    } else if let Some(rest) = job.kind.strip_prefix("arpfilter.switch.") {
        // kind = arpfilter.switch.<old>.<new>
        if let Some(new_mode) = rest.rsplit('.').next() {
            sqlx::query(
                "INSERT INTO arp_mode (host_id, mode, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) \
                 ON CONFLICT(host_id) DO UPDATE SET mode=excluded.mode, updated_at=CURRENT_TIMESTAMP"
            )
            .bind(job.host_id).bind(new_mode).execute(&state.db).await?;
        }
    } else if job.kind.starts_with("arpfilter.uninstall.") {
        sqlx::query("DELETE FROM arp_mode WHERE host_id=?")
            .bind(job.host_id).execute(&state.db).await?;
    }

    // 配置下发成功 = 节点已用新 token 运行：撤销轮换重叠期的 retiring token
    if job.kind == "qos.config_apply" || job.kind == "qos.install" {
        crate::qos::revoke_retiring(&state.db, job.host_id).await?;
    }
    // 卸载成功 = 节点接入凭据全部作废（token 不再可用）
    if job.kind == "qos.uninstall" {
        sqlx::query("UPDATE qos_tokens SET status='revoked' WHERE host_id=? AND status != 'revoked'")
            .bind(job.host_id).execute(&state.db).await?;
    }
    Ok(())
}

/// 组件状态查询
pub async fn component_map(pool: &SqlitePool) -> anyhow::Result<serde_json::Value> {
    let rows: Vec<(i64, String, String, Option<String>)> = sqlx::query_as(
        "SELECT host_id, component, status, detail FROM host_components"
    ).fetch_all(pool).await?;
    let mut map = serde_json::Map::new();
    for (host_id, comp, status, detail) in rows {
        map.entry(host_id.to_string()).or_insert_with(|| json!({}))
            .as_object_mut().unwrap()
            .insert(comp, json!({"status": status, "detail": detail}));
    }
    Ok(json!(map))
}

// ==================== M6 母机优化与初始化 ====================

const NOSUB_SCRIPT: &str = include_str!("../scripts/pve-nosub.sh");
const OPTIMIZE_SCRIPT: &str = include_str!("../scripts/pve-optimize.sh");

fn pve_precheck() -> StepSpec {
    step("环境预检", "pveversion >/dev/null 2>&1 || { echo '不是 PVE 主机'; exit 1; }; echo '预检通过'".into(), None)
}

/// 一键初始化：换 no-subscription 源 + 去弹窗
pub fn optimize_init() -> JobSpec {
    JobSpec {
        kind: "optimize.init".into(),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 300,
        queue_ttl_secs: 1800,
        steps: vec![
            pve_precheck(),
            StepSpec {
                name: "上传 pve-nosub 脚本".into(),
                command: upload_cmd(NOSUB_SCRIPT, "/usr/local/sbin/pve-nosub.sh"),
                rollback_command: Some("rm -f /usr/local/sbin/pve-nosub.sh".into()),
                rerun_safe: true,
            },
            // 恢复确认走管道 echo y；不能加 < /dev/null（会覆盖管道让 read 读到 EOF）
            step("换源与去弹窗", "bash /usr/local/sbin/pve-nosub.sh < /dev/null".into(),
                Some("echo y | bash /usr/local/sbin/pve-nosub.sh --restore".into())),
        ],
    }
}

/// 系统更新（dist-upgrade）：软件包变更无法回滚，独立任务且不声明回滚
pub fn optimize_upgrade() -> JobSpec {
    JobSpec {
        kind: "optimize.upgrade".into(),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 3600,
        queue_ttl_secs: 1800,
        steps: vec![
            pve_precheck(),
            step("系统更新（不可回滚）",
                "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confold dist-upgrade".into(),
                None),
        ],
    }
}

/// 内核参数自适应优化（按硬件分档）；items=None 全量，Some 按选择执行（白名单校验，防命令注入）
pub const OPTIMIZE_ITEMS: [&str; 12] = [
    "ulimit", "systemd_limits", "journald", "sysctl", "bbr", "thp",
    "cpu_governor", "ksm", "io_scheduler", "dmesg", "zfs_arc", "timezone",
];

pub fn optimize_tune(items: Option<Vec<String>>) -> Result<JobSpec, String> {
    let only_arg = match &items {
        None => String::new(),
        Some(list) => {
            if list.is_empty() {
                return Err("至少选择一项优化项".into());
            }
            for it in list {
                if !OPTIMIZE_ITEMS.contains(&it.as_str()) {
                    return Err(format!("未知优化项: {}", it));
                }
            }
            // 去重（保持顺序），保证步骤标签计数与实际执行一致
            let mut seen = std::collections::HashSet::new();
            let deduped: Vec<String> = list.iter().filter(|it| seen.insert(it.clone())).cloned().collect();
            format!(" --only {}", deduped.join(","))
        }
    };
    let label = match &items {
        None => "执行优化（全部项）".to_string(),
        Some(list) => {
            let mut seen = std::collections::HashSet::new();
            let deduped: Vec<&String> = list.iter().filter(|it| seen.insert(it.clone())).collect();
            format!("执行优化（{} 项: {}）", deduped.len(), deduped.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","))
        }
    };
    Ok(JobSpec {
        kind: "optimize.tune".into(),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 600,
        queue_ttl_secs: 1800,
        steps: vec![
            pve_precheck(),
            StepSpec {
                name: "上传 pve-optimize 脚本".into(),
                command: upload_cmd(OPTIMIZE_SCRIPT, "/usr/local/sbin/pve-optimize.sh"),
                rollback_command: Some("rm -f /usr/local/sbin/pve-optimize.sh".into()),
                rerun_safe: true,
            },
            step(&label, format!("bash /usr/local/sbin/pve-optimize.sh{} < /dev/null", only_arg),
                Some("echo y | bash /usr/local/sbin/pve-optimize.sh --restore".into())),
        ],
    })
}

/// 回滚（component = nosub / optimize）
pub fn optimize_rollback(component: &str) -> Option<JobSpec> {
    let script = match component {
        "nosub" => "/usr/local/sbin/pve-nosub.sh",
        "optimize" => "/usr/local/sbin/pve-optimize.sh",
        _ => return None,
    };
    Some(JobSpec {
        kind: format!("optimize.rollback.{}", component),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 300,
        queue_ttl_secs: 1800,
        steps: vec![step(
            "回滚到上次备份",
            format!("echo y | bash {} --restore", script),
            None,
        )],
    })
}

/// 优化状态回采（备份列表 + 各组件落地标记）
pub fn optimize_status() -> JobSpec {
    let cmd = r#"echo '{"nosub":' ; [ -f /etc/apt/apt.conf.d/90pve-no-nag ] && echo -n true || echo -n false
echo -n ',"nosub_sources":' ; ls /etc/apt/sources.list.d/ 2>/dev/null | grep -c 'no-subscription' || true
echo -n ',"optimized":' ; grep -c 'PVE 宿主机优化' /etc/sysctl.conf 2>/dev/null || true
echo -n ',"nosub_backups":"' ; ls -1 /root/pve-nosub-backup 2>/dev/null | tail -3 | tr '\n' ' ' ; echo -n '"'
echo -n ',"optimize_backups":"' ; ls -1 /root/pve-optimize-backup 2>/dev/null | tail -3 | tr '\n' ' ' ; echo -n '"'
echo '}'"#.to_string();
    JobSpec {
        kind: "optimize.status".into(),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 60,
        queue_ttl_secs: 600,
        steps: vec![step("读取优化状态", cmd, None)],
    }
}

// ==================== M7 巡检 ====================

/// 主机巡检任务：资源水位（机器可读输出）+ 已装组件存活检查
/// 输出约定（alerts::evaluate_inspection 解析）：
///   DISK:85 / MEM:62 / LOAD:1.20 / VMRUN:42 / DEAD:<component>
pub async fn inspect_host(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<JobSpec> {
    let mut cmd = String::from(
        r#"echo "DISK:$(df / --output=pcent 2>/dev/null | tail -1 | tr -d ' %')"
echo "MEM:$(free 2>/dev/null | awk '/^Mem:/{printf "%d", $3/$2*100}')"
echo "LOAD:$(cut -d' ' -f1 /proc/loadavg)"
echo "VMRUN:$(qm list 2>/dev/null | awk 'NR>1' | wc -l)""#
    );

    // 已安装组件的存活检查（失效输出 DEAD:<component>）
    let comps: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT component, detail FROM host_components WHERE host_id = ?"
    ).bind(host_id).fetch_all(&state.db).await?;
    let arp_mode: Option<(String,)> = sqlx::query_as("SELECT mode FROM arp_mode WHERE host_id = ?")
        .bind(host_id).fetch_optional(&state.db).await?;

    for (comp, _) in comps {
        match comp.as_str() {
            "netguard" => cmd.push_str("\niptables -S VMNETGUARD >/dev/null 2>&1 || echo 'DEAD:netguard'"),
            "vmqos" => cmd.push_str("\nsystemctl is-active --quiet vmqos || echo 'DEAD:vmqos'"),
            "arpfilter" => {
                let unit = match arp_mode.as_ref().map(|m| m.0.as_str()) {
                    Some("static") => "pve-arpfilter-static",
                    _ => "pve-arpfilter",
                };
                cmd.push_str(&format!("\nsystemctl is-active --quiet {} || echo 'DEAD:arpfilter'", unit));
            }
            _ => {}
        }
    }

    Ok(JobSpec {
        kind: "inspect.host".into(),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 60,
        queue_ttl_secs: 600,
        steps: vec![step("巡检采集", cmd, None)],
    })
}

// ==================== vmqos（P3 带宽 QoS） ====================

const VMQOS_UNIT: &str = "[Unit]\nDescription=vmqos dynamic bandwidth scheduler\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart=/opt/vmqos/vmqos /opt/vmqos/config.toml\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n";

async fn get_setting(pool: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM settings WHERE key=?")
        .bind(key).fetch_optional(pool).await.ok().flatten()
}

/// 平台对节点暴露的基础 URL（渲染 vmqos 配置用，须节点可达）
async fn platform_base(state: &Arc<AppState>) -> anyhow::Result<String> {
    get_setting(&state.db, "platform_public_url").await
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("请先在设置中配置 platform_public_url（节点可达的平台地址）"))
}

/// 组装一台主机的 vmqos config.toml
async fn qos_config(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<String> {
    let base = platform_base(state).await?;
    let snapshot_token = crate::qos::active_token_plain(&state.db, &state.master_key, host_id, "snapshot").await?;
    let report_token = crate::qos::active_token_plain(&state.db, &state.master_key, host_id, "report").await?;
    // 国际站可选：未签发留空（vmqos 仅 warn）；已签发但解密失败 = 失败关闭（静默留空会悄悄断掉国际上报）
    let intl_row: Option<(String,)> = sqlx::query_as(
        "SELECT token_enc FROM qos_tokens WHERE host_id=? AND purpose='intl' AND status='active'"
    ).bind(host_id).fetch_optional(&state.db).await?;
    let intl_token = match intl_row {
        Some((enc,)) => crate::crypto::decrypt(&enc, &state.master_key)
            .map_err(|e| anyhow::anyhow!("国际站 token 解密失败（失败关闭）: {}", e))?,
        None => String::new(),
    };
    let intl_url = if intl_token.is_empty() { String::new() } else { format!("{}/api/v1/vmqos/intl", base) };

    let template: serde_json::Value = match sqlx::query_scalar::<_, i64>("SELECT qos_template_id FROM hosts WHERE id=?")
        .bind(host_id).fetch_one(&state.db).await?
    {
        tid if tid > 0 => {
            let cfg: Option<String> = sqlx::query_scalar("SELECT config_json FROM qos_templates WHERE id=?")
                .bind(tid).fetch_optional(&state.db).await?;
            cfg.and_then(|c| serde_json::from_str(&c).ok()).unwrap_or_else(|| crate::qos::builtin_template())
        }
        _ => crate::qos::builtin_template(),
    };

    crate::qos::render_config(
        &format!("{}/api/v1/vmqos/snapshot", base), &snapshot_token,
        &format!("{}/api/v1/vmqos/qos", base), &report_token,
        &intl_url, &intl_token,
        &template,
    )
}

/// vmqos 安装任务：下载校验 → 安装 → 配置 → systemd；QoS 影响客户 VM 带宽 = fail_closed
pub async fn qos_install(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<JobSpec> {
    let conf = qos_config(state, host_id).await?;
    let version = get_setting(&state.db, "vmqos_version").await.unwrap_or_else(|| "0.0.6".into());
    // 值会插值进 shell 命令：版本号严格 semver，下载基址仅允许 https + 安全字符
    if !version.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') || version.is_empty() {
        return Err(anyhow::anyhow!("vmqos_version 格式非法: {}", version));
    }
    let dl_base = get_setting(&state.db, "vmqos_download_base").await
        .unwrap_or_else(|| "https://github.com/MOSSDATA-NETWORK/vmqos/releases/download".into());
    let dl_base = dl_base.trim().trim_end_matches('/');
    if !dl_base.starts_with("https://") || dl_base.chars().any(|c| !(c.is_ascii_alphanumeric() || "-._/:~".contains(c))) {
        return Err(anyhow::anyhow!("vmqos_download_base 非法（仅允许 https URL）"));
    }
    let fname = format!("vmqos-linux-amd64-v{}", version);
    // 配置了镜像 token（私有仓库）→ 节点经平台代理下载（带快照 token 鉴权）；
    // 否则直连公开仓库
    let dl_cmd = if crate::qos::github_mirror_token(state).await.is_some() {
        let base = platform_base(state).await?;
        let snap_tok = crate::qos::active_token_plain(&state.db, &state.master_key, host_id, "snapshot").await?;
        format!(
            "cd /tmp && curl -fsSL --connect-timeout 15 -H 'Authorization: Bearer {t}' -o {f} '{b}/api/v1/vmqos/agent/v{v}/{f}' && curl -fsSL --connect-timeout 15 -H 'Authorization: Bearer {t}' -o {f}.sums '{b}/api/v1/vmqos/agent/v{v}/vmqos-v{v}-SHA256SUMS.txt' && grep ' {f}$' {f}.sums | sha256sum -c -",
            f = fname, b = base, v = version, t = snap_tok
        )
    } else {
        format!(
            "cd /tmp && curl -fsSL --connect-timeout 15 -o {f} '{b}/v{v}/{f}' && curl -fsSL --connect-timeout 15 -o {f}.sums '{b}/v{v}/vmqos-v{v}-SHA256SUMS.txt' && grep ' {f}$' {f}.sums | sha256sum -c -",
            f = fname, b = dl_base, v = version
        )
    };

    Ok(JobSpec {
        kind: "qos.install".into(),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 600,
        queue_ttl_secs: 3600,
        steps: vec![
            step("前置检查", "command -v qm >/dev/null && command -v systemctl >/dev/null && command -v curl >/dev/null && command -v sha256sum >/dev/null".into(), None),
            StepSpec {
                name: "下载并校验 vmqos 二进制".into(),
                command: dl_cmd,
                rollback_command: Some(format!("rm -f /tmp/{} /tmp/{}.sums", fname, fname)),
                rerun_safe: true,
            },
            StepSpec {
                name: "安装二进制".into(),
                command: format!("mkdir -p /opt/vmqos && [ ! -f /opt/vmqos/vmqos ] || cp -a /opt/vmqos/vmqos /opt/vmqos/vmqos.bak; install -m0755 /tmp/{} /opt/vmqos/vmqos", fname),
                rollback_command: Some("[ -f /opt/vmqos/vmqos.bak ] && mv /opt/vmqos/vmqos.bak /opt/vmqos/vmqos || rm -f /opt/vmqos/vmqos".into()),
                rerun_safe: true,
            },
            StepSpec {
                name: "下发配置".into(),
                command: format!("[ -f /opt/vmqos/config.toml ] && cp -a /opt/vmqos/config.toml /opt/vmqos/config.toml.bak; echo '{}' | base64 -d > /opt/vmqos/config.toml.tmp && chmod 600 /opt/vmqos/config.toml.tmp && /opt/vmqos/vmqos --check-config /opt/vmqos/config.toml.tmp && mv /opt/vmqos/config.toml.tmp /opt/vmqos/config.toml", b64(&conf)),
                rollback_command: Some("[ -f /opt/vmqos/config.toml.bak ] && mv /opt/vmqos/config.toml.bak /opt/vmqos/config.toml || rm -f /opt/vmqos/config.toml".into()),
                rerun_safe: true,
            },
            StepSpec {
                name: "注册并启动服务".into(),
                command: format!("echo '{}' | base64 -d > /etc/systemd/system/vmqos.service && systemctl daemon-reload && systemctl enable --now vmqos", b64(VMQOS_UNIT)),
                rollback_command: Some("systemctl disable --now vmqos; rm -f /etc/systemd/system/vmqos.service; systemctl daemon-reload".into()),
                rerun_safe: true,
            },
            step("验证运行", "sleep 2 && systemctl is-active --quiet vmqos".into(),
                Some("systemctl stop vmqos".into())),
        ],
    })
}

/// 配置下发（模板变更/token 轮换后）：备份 → 校验 → 原子替换 → 重启；成功后撤销 retiring token
pub async fn qos_config_apply(state: &Arc<AppState>, host_id: i64) -> anyhow::Result<JobSpec> {
    let conf = qos_config(state, host_id).await?;
    Ok(JobSpec {
        kind: "qos.config_apply".into(),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 120,
        queue_ttl_secs: 1800,
        steps: vec![
            step("备份当前配置", "cp -a /opt/vmqos/config.toml /opt/vmqos/config.toml.qosbak".into(), None),
            StepSpec {
                name: "下发新配置".into(),
                command: format!("echo '{}' | base64 -d > /opt/vmqos/config.toml.tmp && chmod 600 /opt/vmqos/config.toml.tmp && /opt/vmqos/vmqos --check-config /opt/vmqos/config.toml.tmp && mv /opt/vmqos/config.toml.tmp /opt/vmqos/config.toml", b64(&conf)),
                rollback_command: Some("cp -a /opt/vmqos/config.toml.qosbak /opt/vmqos/config.toml && systemctl restart vmqos".into()),
                rerun_safe: true,
            },
            step("重启并验证", "systemctl restart vmqos && sleep 2 && systemctl is-active --quiet vmqos".into(),
                Some("cp -a /opt/vmqos/config.toml.qosbak /opt/vmqos/config.toml && systemctl restart vmqos".into())),
        ],
    })
}

pub fn qos_uninstall() -> JobSpec {
    JobSpec {
        kind: "qos.uninstall".into(),
        failure_policy: POLICY_FAIL_CLOSED.into(),
        timeout_secs: 120,
        queue_ttl_secs: 1800,
        steps: vec![step("卸载 vmqos",
            "systemctl disable --now vmqos 2>/dev/null; rm -f /etc/systemd/system/vmqos.service /opt/vmqos/vmqos /opt/vmqos/vmqos.bak /opt/vmqos/config.toml /opt/vmqos/config.toml.bak /opt/vmqos/config.toml.qosbak; systemctl daemon-reload; echo '已卸载（保留 /var/lib/vmqos 快照归档）'".into(),
            None)],
    }
}

pub fn qos_status() -> JobSpec {
    JobSpec {
        kind: "qos.status".into(),
        failure_policy: POLICY_FAIL_OPEN.into(),
        timeout_secs: 60,
        queue_ttl_secs: 600,
        steps: vec![step("读取状态",
            "systemctl is-active vmqos; /opt/vmqos/vmqos --version 2>/dev/null || echo 'version unknown'; /opt/vmqos/vmqos --check-config /opt/vmqos/config.toml && echo 'config ok'".into(),
            None)],
    }
}
