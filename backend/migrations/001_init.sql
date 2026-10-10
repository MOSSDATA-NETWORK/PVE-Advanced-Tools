-- 设置表（密钥等）
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    totp_secret TEXT,
    passkey_credential TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 会话表
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    ip TEXT,
    user_agent TEXT,
    expires_at DATETIME NOT NULL,
    mfa_verified INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);

-- PVE 主机
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER DEFAULT 22,
    username TEXT DEFAULT 'root',
    auth_type TEXT DEFAULT 'password',
    password_encrypted TEXT,
    ssh_key_encrypted TEXT,
    api_token_encrypted TEXT,
    status TEXT DEFAULT 'unknown',
    agent_deployed INTEGER DEFAULT 0,
    last_check DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 扫描任务
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending',
    total_vms INTEGER DEFAULT 0,
    ga_count INTEGER DEFAULT 0,
    disk_count INTEGER DEFAULT 0,
    found_count INTEGER DEFAULT 0,
    started_at DATETIME,
    completed_at DATETIME,
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 检测结果
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    vmid TEXT NOT NULL,
    status TEXT NOT NULL,
    method TEXT,
    evidence TEXT,
    first_seen DATETIME,
    last_seen DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 通知配置
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    config_encrypted TEXT NOT NULL,
    notify_level TEXT DEFAULT 'detected_and_cleaned',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 定时任务
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    cron_expr TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    last_run DATETIME,
    next_run DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
