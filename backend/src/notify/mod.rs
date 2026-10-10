use serde::Deserialize;
use sqlx::SqlitePool;

#[derive(Debug, Deserialize)]
struct TelegramConfig {
    bot_token: String,
    chat_id: String,
}

#[derive(Debug, Deserialize)]
struct WecomConfig {
    webhook: String,
}

pub async fn test_telegram(config_str: &str) -> Result<String, String> {
    let config: TelegramConfig = serde_json::from_str(config_str).map_err(|e| format!("配置解析失败: {}", e))?;
    let msg = "🧪 Chicken Detect 测试通知\n\n如果您收到此消息，说明 Telegram 通知配置正确。";
    send_telegram(&config.bot_token, &config.chat_id, msg).await
}

pub async fn test_wecom(config_str: &str) -> Result<String, String> {
    let config: WecomConfig = serde_json::from_str(config_str).map_err(|e| format!("配置解析失败: {}", e))?;
    let msg = "## 🧪 Chicken Detect 测试通知\n\n如果您收到此消息，说明企业微信通知配置正确。";
    send_wecom(&config.webhook, msg).await
}

pub async fn send_telegram(bot_token: &str, chat_id: &str, text: &str) -> Result<String, String> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let resp = client.post(&url)
        .json(&serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML"
        }))
        .send()
        .await
        .map_err(|e| format!("请求失败: {}", e))?;

    if resp.status().is_success() {
        Ok("发送成功".to_string())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

pub async fn send_wecom(webhook: &str, text: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let resp = client.post(webhook)
        .json(&serde_json::json!({
            "msgtype": "markdown",
            "markdown": { "content": text }
        }))
        .send()
        .await
        .map_err(|e| format!("请求失败: {}", e))?;

    if resp.status().is_success() {
        Ok("发送成功".to_string())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

pub async fn send_all(pool: &SqlitePool, master_key: &[u8], status: &str, host_name: &str, vmid: &str, evidence: &str) {
    let notifications = match crate::db::list_notifications(pool).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("Failed to load notifications: {}", e);
            return;
        }
    };

    let (emoji, label) = match status {
        "detected" => ("🚨", "新发现"),
        "confirmed" => ("⚠️", "持续存在"),
        "cleaned" => ("✅", "已清除"),
        _ => ("❓", "未知"),
    };

    for n in &notifications {
        if !n.enabled { continue; }

        // Check notify level
        match n.notify_level.as_str() {
            "detected_only" if status != "detected" => continue,
            "detected_and_cleaned" if status == "confirmed" => continue,
            "detected_and_confirmed" if status == "cleaned" => continue,
            _ => {}
        }

        // 解密配置
        let config = match crate::crypto::decrypt(&n.config_encrypted, master_key) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Notification config decrypt failed: {}", e);
                continue;
            }
        };

        let result = match n.r#type.as_str() {
            "telegram" => {
                let msg = format!(
                    "<b>{} 切鸡检测 [{}]</b>\n宿主机: <code>{}</code>\nVM: <code>{}</code>\n证据: <code>{}</code>\n时间: {}",
                    emoji, label, host_name, vmid, evidence, chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                );
                if let Ok(cfg) = serde_json::from_str::<TelegramConfig>(&config) {
                    send_telegram(&cfg.bot_token, &cfg.chat_id, &msg).await
                } else {
                    Err("Telegram 配置解析失败".to_string())
                }
            }
            "wecom" => {
                let msg = format!(
                    "## {} 切鸡检测 [{}]\n- **宿主机**: {}\n- **VM**: {}\n- **证据**: {}\n- **时间**: {}",
                    emoji, label, host_name, vmid, evidence, chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                );
                if let Ok(cfg) = serde_json::from_str::<WecomConfig>(&config) {
                    send_wecom(&cfg.webhook, &msg).await
                } else {
                    Err("企业微信配置解析失败".to_string())
                }
            }
            _ => continue,
        };

        if let Err(e) = result {
            tracing::warn!("Notification send failed ({}): {}", n.r#type, e);
        }
    }
}

/// 通用告警通知（M7 巡检告警用，与检测告警共用渠道配置）
/// 返回成功送达的渠道数（0 = 无渠道或全部失败）
pub async fn send_alert(pool: &SqlitePool, master_key: &[u8], title: &str, message: &str) -> usize {
    let notifications = match crate::db::list_notifications(pool).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("Failed to load notifications: {}", e);
            return 0;
        }
    };

    let mut sent = 0usize;
    for n in &notifications {
        if !n.enabled { continue; }

        let config = match crate::crypto::decrypt(&n.config_encrypted, master_key) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Notification config decrypt failed: {}", e);
                continue;
            }
        };

        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let result = match n.r#type.as_str() {
            "telegram" => {
                let msg = format!("<b>🛎 {}</b>\n{}\n时间: {}", title, message, now);
                if let Ok(cfg) = serde_json::from_str::<TelegramConfig>(&config) {
                    send_telegram(&cfg.bot_token, &cfg.chat_id, &msg).await
                } else {
                    Err("Telegram 配置解析失败".to_string())
                }
            }
            "wecom" => {
                let msg = format!("## 🛎 {}\n{}\n- **时间**: {}", title, message, now);
                if let Ok(cfg) = serde_json::from_str::<WecomConfig>(&config) {
                    send_wecom(&cfg.webhook, &msg).await
                } else {
                    Err("企业微信配置解析失败".to_string())
                }
            }
            _ => continue,
        };

        match result {
            Ok(_) => sent += 1,
            Err(e) => tracing::warn!("Alert send failed ({}): {}", n.r#type, e),
        }
    }
    sent
}
