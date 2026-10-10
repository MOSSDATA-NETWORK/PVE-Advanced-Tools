-- P0 base: audit log, SSH job framework, VM stable identity, host capability probing.
-- Applied statement-by-statement by the migrator; safe to re-run
-- (CREATE uses IF NOT EXISTS, duplicate-column ALTER errors are ignored).

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail TEXT,
    ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);

-- hosts extension: pinned SSH host key (TOFU confirm, anti-MITM) and capability probe
ALTER TABLE hosts ADD COLUMN host_key_fingerprint TEXT;
ALTER TABLE hosts ADD COLUMN host_key_known_hosts TEXT;
ALTER TABLE hosts ADD COLUMN host_key_status TEXT DEFAULT 'pending';
ALTER TABLE hosts ADD COLUMN pve_version TEXT;
ALTER TABLE hosts ADD COLUMN capabilities TEXT;

-- jobs: per-host serial execution (host lock in app layer), seq monotonic per host
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    seq INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    failure_policy TEXT NOT NULL DEFAULT 'fail_closed',
    checkpoint_step INTEGER DEFAULT 0,
    timeout_secs INTEGER DEFAULT 300,
    queue_ttl_secs INTEGER DEFAULT 1800,
    error TEXT,
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    started_at DATETIME,
    finished_at DATETIME
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_host_seq ON jobs(host_id, seq);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);

CREATE TABLE IF NOT EXISTS job_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    name TEXT NOT NULL,
    command TEXT NOT NULL,
    rollback_command TEXT,
    rerun_safe INTEGER NOT NULL DEFAULT 1 CHECK (rerun_safe IN (0,1)),
    status TEXT NOT NULL DEFAULT 'pending',
    output TEXT,
    exit_code INTEGER,
    started_at DATETIME,
    finished_at DATETIME,
    UNIQUE(job_id, seq)
);

-- desired state: baseline for whole-host reconciliation after reboot
CREATE TABLE IF NOT EXISTS desired_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    applied_job_id INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, kind)
);

-- VM stable identity: SMBIOS UUID first, node+VMID fallback.
-- Only one active binding per (host_id, vmid); on VMID reuse the old binding goes stale.
CREATE TABLE IF NOT EXISTS vms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vmid INTEGER NOT NULL,
    smbios_uuid TEXT,
    name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vms_active ON vms(host_id, vmid) WHERE status = 'active';
-- 存量 UUID 统一小写规范化（索引区分大小写，入库约定为小写）
UPDATE vms SET smbios_uuid = lower(smbios_uuid) WHERE smbios_uuid IS NOT NULL;
-- 同一主机同一 SMBIOS UUID 只允许一条 active 绑定（防 UUID 串扰产生两个活动身份）
CREATE UNIQUE INDEX IF NOT EXISTS idx_vms_uuid_active ON vms(host_id, smbios_uuid) WHERE status = 'active' AND smbios_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vms_uuid ON vms(smbios_uuid);

-- identity change events (migration/clone/HA rebuild/VMID reuse audit trail)
CREATE TABLE IF NOT EXISTS vm_identity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    vmid INTEGER NOT NULL,
    old_uuid TEXT,
    new_uuid TEXT,
    reason TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vm_events_host ON vm_identity_events(host_id, vmid);
