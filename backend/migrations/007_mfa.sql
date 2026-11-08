-- 待确认的 TOTP 密钥（确认前不影响已启用的 totp_secret）
ALTER TABLE users ADD COLUMN totp_pending_secret TEXT;
-- 升级后作废旧会话，新的二次验证规则立即生效
DELETE FROM sessions;
