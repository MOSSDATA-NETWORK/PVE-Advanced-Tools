-- 补丁功能：切鸡特征库（M2）+ ARP 效果统计采样（M4）

-- 自定义检测特征：下发到节点 /etc/chicken-signatures.conf，chicken-check.sh 运行时读取
CREATE TABLE detect_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    sig_type TEXT NOT NULL CHECK (sig_type IN ('path','service','history')),
    value TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(sig_type, value)
);

-- ARP 降噪效果采样：arpfilter stats 任务回采的丢弃计数（计数器随规则表重建清零，
-- 语义为「节点最近一次应用以来」）
CREATE TABLE arp_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vm_drops TEXT NOT NULL DEFAULT '{}',
    bpdu_drops INTEGER NOT NULL DEFAULT 0,
    collected_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_arp_stats_host ON arp_stats(host_id, collected_at);
