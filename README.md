# PVE Advanced Tools

**English** | [简体中文](README.zh-CN.md)

An all-in-one management platform for **Proxmox VE** hypervisors, built for VPS operators.
One web console to manage many PVE hosts: **abuse detection + network control + performance tuning + bandwidth QoS + inspection & alerts** — replacing scattered shell scripts with a single auditable system.

- **Backend**: Rust + Axum + SQLite (single binary, frontend embedded)
- **Frontend**: Vue 3 + Vite
- **Node-side execution**: SSH job runner (no permanent platform agent on nodes); the only resident node components are the ones being managed (vmqos daemon, systemd services)

## Features

### Detection (inherited from the Noqjj base)
- Guest-agent / disk-signature abuse scanning across all VMs on a host, with scheduled scans and result history

### Network Control
- **Egress firewall (netguard)**: per-host port/domain blocking with atomic iptables chain swap, VMID whitelist, backup & rollback
- **ARP noise reduction (arpfilter)**: passive / static modes, atomic single-job mode switching, whitelist and static-mapping push

### Performance Tuning
- One-click initialization (no-subscription repos, subscription nag removal)
- Kernel/sysctl/THP/KSM/IO-scheduler/ZFS-ARC tuning with manifest-based backup and rollback

### Bandwidth QoS (vmqos integration)
- Platform implements the **vmqos snapshot API contract (schema v2)** — vmqos runs unmodified on nodes and pulls its policy snapshot from this platform
- Per-VM base rate policies (domestic / international sources), stage-ladder templates (node-level), rate-limit event stream, node health (fresh / degraded / stale)
- Per-node access tokens with overlap rotation (old token revoked only after the new config is live)

### Platform Foundation
- **SSH job runner**: HMAC-SHA256 signed task packages, per-step checkpoints, per-host serial execution, fail-open / fail-closed failure policies, queue TTL, boot-time reconciliation, step-level rollback
- **SSH host-key pinning (TOFU)**: fingerprint confirmation workflow, platform-managed `known_hosts`, `StrictHostKeyChecking=yes` after confirmation
- **Stable VM identity**: SMBIOS UUID first, node+VMID fallback, automatic rebind with audit trail
- **Inspection & alerts**: periodic host inspection (disk / memory / load / VM count / component liveness), Telegram & WeCom notifications, deduplicated alert engine
- **Audit log**: every sensitive operation recorded and searchable
- **Online update**: GitHub Releases check, SHA256SUMS + ed25519 signature verification (fail-closed), atomic binary swap, automatic SQLite & binary backup, boot self-check with `.bak` rollback
- **Auth**: password + TOTP 2FA + passkey, login rate limiting, loopback-only initial setup

## Requirements

| Component | Requirement |
|---|---|
| Management host | Linux (x86_64/aarch64) or macOS; ~50 MB RAM |
| Managed nodes | Proxmox VE 7 / 8 / 9, root SSH access |
| Node tools | `curl`, `sha256sum`, `iptables`, `python3` (arpfilter), `systemd` |

## Deployment

### Option A — Prebuilt binary (recommended)

Download from [Releases](https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases) and verify:

```bash
curl -fSLO https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases/latest/download/pve-advanced-tools-linux-x86_64
curl -fSLO https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases/latest/download/SHA256SUMS
grep pve-advanced-tools-linux-x86_64 SHA256SUMS | sha256sum -c -
chmod +x pve-advanced-tools-linux-x86_64
```

### Option B — Build from source

```bash
# Frontend (embedded into the binary's static dir)
cd frontend && npm install && npm run build   # outputs to backend/static

# Backend
cd ../backend && cargo build --release        # target/release/pve-advanced-tools-backend
```

### Install as a service

```bash
sudo bash deploy/install.sh [port]   # default port 3210
```

The installer:
- copies the binary + frontend assets to `/opt/pve-advanced-tools`
- **generates and persists `MASTER_KEY`** in `/opt/pve-advanced-tools/env` (mode 600) — reused on reinstall
- registers and starts the `pve-advanced-tools` systemd unit

**Create the admin account** (either way):

1. **Environment bootstrap (recommended for headless servers)**: set `INITIAL_ADMIN_USERNAME=admin` and
   `INITIAL_ADMIN_PASSWORD=<strong-password>` before first start (with install.sh, append them to
   `/opt/pve-advanced-tools/env`). The account is created on first boot — **remove both variables and restart afterwards**.
2. **SSH tunnel**: `ssh -L 3210:127.0.0.1:3210 root@server`, then open `http://127.0.0.1:3210` for the web setup
   (the web setup endpoint is loopback-only so nobody can race you to create the admin once the domain is live).

After initialization, everyday access through your reverse-proxied domain is unrestricted.

### Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `MASTER_KEY` | auto-generated (printed once) | **Required in production.** 64-char hex key encrypting stored credentials. Losing or changing it makes stored credentials unreadable (fail-closed). |
| `DATABASE_URL` | `sqlite:pve-advanced-tools.db?mode=rwc` | SQLite path |
| `PORT` / `HOST` | `3210` / `0.0.0.0` | Listen address |
| `TLS_CERT` / `TLS_KEY` | — | Direct TLS; or set `BEHIND_TLS_PROXY=1` behind an HTTPS reverse proxy |
| `STATIC_DIR` | `static` | Frontend assets |
| `DATA_DIR` | `data` | Runtime files (managed `known_hosts`) |
| `UPDATE_SIGN_PUBKEY` | — | ed25519 public key (hex) for update signature verification. If set, releases must carry a valid `.sig`; if unset, online update is refused (fail-closed) |
| `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` | — | Bootstrap admin on first boot (only when no admin exists); remove after creation |
| `UPDATE_GITHUB_REPO` | `MOSSDATA-NETWORK/PVE-Advanced-Tools` | Update source |
| `platform_public_url` (panel setting) | — | Node-reachable platform URL, required before pushing vmqos configs |

## Quick start

1. **Settings** → set `platform_public_url` (e.g. `https://panel.example.com`)
2. **Hosts** → add a PVE node (SSH credentials) → confirm the SSH fingerprint (TOFU)
3. Component tabs (**出网管控 / ARP 降噪 / 母机优化 / 带宽 QoS**) → install / configure per host; every action runs as an auditable, rollback-capable job (**任务** page)
4. **带宽 QoS**: issue node tokens → install vmqos → add per-VM rate policies → nodes pull their snapshot and start dynamic rate limiting; events appear in the QoS event stream
5. **告警与巡检**: configure Telegram / WeCom channels, tune inspection interval and alert rules

## Update & rollback

- **Panel**: Settings → check for updates → one-click update (SHA256SUMS + ed25519 signature enforced)
- **Rollback**: restore `<binary>.bak` and `<db>.bak` (both written next to the originals before every update), then restart the service

## Security notes

- SSH host keys are pinned after explicit fingerprint confirmation; address changes invalidate the confirmation
- Credentials are encrypted with AES-256-GCM; decryption failure is fail-closed
- Node-facing API tokens are stored as hashes (verification) + AES-GCM ciphertext (provisioning); rotation overlaps until the new config is confirmed live
- vmqos downloads on nodes are verified against the release SHA256SUMS before installation

## Attribution

Copyright © MOSSDATA. Maintained by **mossdata**.

Integrates components from: Noqjj (detection base), PVE-shell (ops script collection), vmqos (node bandwidth scheduler — used unmodified, via its snapshot API contract).

## License

Unless a LICENSE file states otherwise, all rights reserved by the repository owner. Contact MOSSDATA before commercial reuse.
