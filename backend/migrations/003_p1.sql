-- P1: netguard (outbound control) + arpfilter (ARP noise filter) platform tables

-- host component install state (netguard / arpfilter / vmqos / optimize ...)
CREATE TABLE IF NOT EXISTS host_components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    component TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'installed',
    detail TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, component)
);

-- netguard: custom drop-port entries (builtin SMTP/BT template seeded by app)
CREATE TABLE IF NOT EXISTS netguard_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ports TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- netguard: domain block entries
CREATE TABLE IF NOT EXISTS netguard_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- netguard: per-host scope (row present + enabled = rules applied on this host)
CREATE TABLE IF NOT EXISTS netguard_scope (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- netguard: per-host VM whitelist (exempt by VMID, mapped to tap interfaces on node)
CREATE TABLE IF NOT EXISTS netguard_whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vmid INTEGER NOT NULL,
    note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, vmid)
);

-- arpfilter: per-host running mode (absent row = not installed)
CREATE TABLE IF NOT EXISTS arp_mode (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('passive', 'static')),
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- arpfilter static mode: VMID/NIC -> IPv4 mapping pushed to node map files
CREATE TABLE IF NOT EXISTS arp_maps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vmid INTEGER NOT NULL,
    nic INTEGER NOT NULL DEFAULT 0,
    ip TEXT NOT NULL,
    UNIQUE(host_id, vmid, nic, ip)
);

-- arpfilter: gray whitelist (only listed VMIDs get rules when non-empty)
CREATE TABLE IF NOT EXISTS arp_whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vmid INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, vmid)
);
