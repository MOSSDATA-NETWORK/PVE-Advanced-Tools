/// 简易速率限制器（内存存储）
/// 用于登录等敏感接口的暴力破解防护
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

const MAX_ENTRIES: usize = 10000; // 最大条目数，防止内存耗尽

/// 内存速率限制器
pub struct RateLimiter {
    /// key -> (失败次数, 首次失败时间)
    attempts: Arc<Mutex<HashMap<String, (u32, std::time::Instant)>>>,
    max_attempts: u32,
    window_secs: u64,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        let attempts: Arc<Mutex<HashMap<String, (u32, std::time::Instant)>>> = Arc::new(Mutex::new(HashMap::new()));

        // 后台定期清理过期条目
        let cleanup_attempts = attempts.clone();
        let cleanup_window = window_secs;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                let mut map = cleanup_attempts.lock().await;
                map.retain(|_, (_, first)| first.elapsed().as_secs() <= cleanup_window);
            }
        });

        Self {
            attempts,
            max_attempts,
            window_secs,
        }
    }

    /// 检查是否被限制（true = 允许，false = 被限制）
    pub async fn check(&self, key: &str) -> bool {
        let mut attempts = self.attempts.lock().await;
        if let Some((count, first)) = attempts.get(key) {
            if first.elapsed().as_secs() > self.window_secs {
                attempts.remove(key);
                return true;
            }
            if *count >= self.max_attempts {
                return false;
            }
        }
        true
    }

    /// 记录一次失败
    pub async fn record_failure(&self, key: &str) {
        let mut attempts = self.attempts.lock().await;

        // 容量检查：超过上限时清理最旧的条目
        if attempts.len() >= MAX_ENTRIES {
            if let Some(oldest_key) = attempts.iter()
                .min_by_key(|(_, (_, first))| first.elapsed())
                .map(|(k, _)| k.clone())
            {
                attempts.remove(&oldest_key);
            }
        }

        if let Some((count, first)) = attempts.get_mut(key) {
            if first.elapsed().as_secs() > self.window_secs {
                *count = 1;
                *first = std::time::Instant::now();
            } else {
                *count += 1;
            }
        } else {
            attempts.insert(key.to_string(), (1, std::time::Instant::now()));
        }
    }

    /// 成功登录后清除记录
    pub async fn clear(&self, key: &str) {
        let mut attempts = self.attempts.lock().await;
        attempts.remove(key);
    }

    /// 获取剩余等待时间（秒）
    pub async fn remaining_secs(&self, key: &str) -> u64 {
        let attempts = self.attempts.lock().await;
        if let Some((count, first)) = attempts.get(key) {
            if *count >= self.max_attempts {
                let elapsed = first.elapsed().as_secs();
                if elapsed < self.window_secs {
                    return self.window_secs - elapsed;
                }
            }
        }
        0
    }
}
