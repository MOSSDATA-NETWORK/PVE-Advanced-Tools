-- P4: alert rules/history + inspection settings

CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('host_offline','job_failed','resource_high','inspect_failed')),
    threshold INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER,
    level TEXT NOT NULL DEFAULT 'warning',
    title TEXT NOT NULL,
    message TEXT,
    host_id INTEGER,
    notified INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alert_history_created ON alert_history(created_at);
-- 每种触发类型只允许一条规则（阈值评估确定性）
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_rules_trigger ON alert_rules(trigger_type);
