-- P3：带宽 QoS（整合 vmqos，schema v2 契约兼容层 + 面板管理）

-- 集群：契约要求顶层 clusters 非空且 service.cluster_id 属于其中
CREATE TABLE clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO clusters (id, name) VALUES (1, '默认集群');

-- 主机归属集群（显式回填默认集群；新主机创建时选择）
ALTER TABLE hosts ADD COLUMN cluster_id INTEGER NOT NULL DEFAULT 1 REFERENCES clusters(id);
-- 节点当前生效的档位模板（节点级，vmqos [stages] 全局单份）
ALTER TABLE hosts ADD COLUMN qos_template_id INTEGER REFERENCES qos_templates(id);

-- 阶梯档位模板：内容为 vmqos config.toml [stages] 段的结构化 JSON
CREATE TABLE qos_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    config_json TEXT NOT NULL,
    builtin INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- VM 带宽策略：initial_mbps 为快照基础速率（vmqos 档位计算基准）；
-- net2_mbps 为国内专线最终值（可选）；initial_mbps=0 表示保留状态但跳过限速
CREATE TABLE qos_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vm_uuid TEXT,
    vmid TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('domestic','international')),
    initial_mbps INTEGER NOT NULL DEFAULT 0,
    net2_mbps INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, vmid, origin)
);

-- 节点接入 token：哈希用于校验，AES-GCM 密文用于下发配置；双 token 重叠轮换
CREATE TABLE qos_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('snapshot','report','intl')),
    token_hash TEXT NOT NULL,
    token_enc TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retiring','revoked')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME
);
CREATE UNIQUE INDEX idx_qos_tokens_active ON qos_tokens(host_id, purpose) WHERE status != 'revoked';
CREATE INDEX idx_qos_tokens_hash ON qos_tokens(token_hash);

-- 限速事件流：无单调序号（vmqos 协议限制），按内容哈希 + 时间窗去重
CREATE TABLE qos_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    origin TEXT NOT NULL DEFAULT 'domestic',
    vmid TEXT NOT NULL,
    stage INTEGER NOT NULL,
    limit_mbps REAL,
    dedup_hash TEXT NOT NULL,
    reported_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_qos_events_host_time ON qos_events(host_id, reported_at);
CREATE INDEX idx_qos_events_dedup ON qos_events(dedup_hash, reported_at);

-- 当前档位状态：支撑 stage 核验端点（vmqos GET api/stage / intl stage）
CREATE TABLE qos_vm_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    origin TEXT NOT NULL DEFAULT 'domestic',
    vmid TEXT NOT NULL,
    current_stage INTEGER NOT NULL DEFAULT 0,
    current_limit REAL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, vmid, origin)
);

-- 节点状态证据：vmqos 无心跳端点，以快照拉取与上报时间推断 fresh/degraded/stale
CREATE TABLE qos_node_status (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    last_snapshot_at DATETIME,
    last_report_at DATETIME,
    last_error TEXT
);

-- 已下发快照归档（每主机仅留最新一份，审计/排障用）
CREATE TABLE qos_snapshots (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL,
    pulled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    raw_json TEXT NOT NULL
);
