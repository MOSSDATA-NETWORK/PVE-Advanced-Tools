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
- **Online update**: GitHub Releases check, SHA256SUMS verification (fail-closed), atomic binary swap (the web UI is built into the binary and updates with it), automatic SQLite & binary backup, boot self-check with `.bak` rollback
- **Auth**: password + TOTP, or a passkey alone; one of the two must be bound during setup; login rate limiting; first-run admin via the web setup (open until the first admin exists) or `INITIAL_ADMIN_*` env bootstrap

## Requirements

| Component | Requirement |
|---|---|
| Management host | Prebuilt binary: Linux x86_64 with glibc 2.36 or newer (Debian 12+); Docker image: any x86_64 Docker host; other platforms: build from source. ~50 MB RAM |
| Managed nodes | Proxmox VE 7 / 8 / 9, root SSH access |
| Node tools | `curl`, `sha256sum`, `iptables`, `python3` (arpfilter), `systemd` |

## Deployment

### Option A — Prebuilt binary (recommended)

Download from [Releases](https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases) and verify:

```bash
curl -fSLO https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases/latest/download/pve-advanced-tools-linux-x86_64
curl -fSLO https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases/latest/download/SHA256SUMS
grep pve-advanced-tools-linux-x86_64 SHA256SUMS | sha256sum -c -

# install as a service (below) from a checkout of this repository
git clone https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools.git
install -m 755 pve-advanced-tools-linux-x86_64 PVE-Advanced-Tools/pve-advanced-tools
sudo bash PVE-Advanced-Tools/deploy/install.sh
```

The web UI and database migrations are built into the binary; nothing else needs copying.

### Option B — Build from source

```bash
# Frontend first: its output (backend/static) is built into the binary
cd frontend && npm install && npm run build   # outputs to backend/static

# Backend
cd ../backend && cargo build --release        # target/release/pve-advanced-tools-backend
```

### Install as a service

```bash
sudo bash deploy/install.sh [port]   # default port 3210
```

The installer:
- copies the binary to `/opt/pve-advanced-tools` (the web UI is built into it)
- **generates and persists `MASTER_KEY`** in `/opt/pve-advanced-tools/env` (mode 600) — reused on reinstall
- registers and starts the `pve-advanced-tools` systemd unit

**Create the admin account** (either way):

1. **Environment bootstrap (recommended for headless servers)**: set `INITIAL_ADMIN_USERNAME=admin` and
   `INITIAL_ADMIN_PASSWORD=<strong-password>` before first start (with install.sh, append them to
   `/opt/pve-advanced-tools/env`). The account is created on first boot — **remove both variables and restart afterwards**.
   That admin must bind TOTP or a passkey at its first sign-in.
2. **Web setup**: open `http://<server or domain>:3210`. The page asks for a username and password, then requires binding TOTP or a passkey.
   Anyone can reach the setup page until the first admin exists; finish it right after deployment.
   To use a tunnel instead: `ssh -L 3210:127.0.0.1:3210 root@server`, then open `http://127.0.0.1:3210`.

After initialization, everyday access through your reverse-proxied domain is unrestricted. TOTP or a passkey is bound during setup (one of the two); the other can be added later in Settings as a backup.

### Docker

The image is attached to each release as a file (there is no registry to pull from):

```bash
curl -fSLO https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases/latest/download/pve-advanced-tools-docker-linux-x86_64.tar.gz
curl -fSLO https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases/latest/download/SHA256SUMS
grep pve-advanced-tools-docker-linux-x86_64.tar.gz SHA256SUMS | sha256sum -c -
docker load -i pve-advanced-tools-docker-linux-x86_64.tar.gz   # tags pve-advanced-tools:<version> and :latest

curl -fSLO https://raw.githubusercontent.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/main/deploy/docker/docker-compose.yml
docker compose up -d
# or: docker run -d --name pve-advanced-tools --init --restart unless-stopped \
#       -p 3210:3210 -v pve-advanced-tools-data:/data pve-advanced-tools:latest
```

- Data (database, `master.key`, `known_hosts`) lives in the `pve-advanced-tools-data` volume. The first start generates `MASTER_KEY` into `/data/master.key`; back it up together with the volume. If the database is there but `master.key` is missing, the container refuses to start instead of creating a new key that cannot read the stored credentials.
- To keep the data in a host directory instead, `chown 10001:10001` that directory first (the container runs as user 10001).
- Behind an HTTPS reverse proxy, set `BEHIND_TLS_PROXY=1` (and optionally `RP_ORIGIN`) in the compose file so passkeys work.
- Create the admin account as described above (web setup or `INITIAL_ADMIN_*` variables).

### Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `MASTER_KEY` | auto-generated (printed once) | **Required in production.** 64-char hex key encrypting stored credentials. Losing or changing it makes stored credentials unreadable (fail-closed). |
| `DATABASE_URL` | `sqlite:pve-advanced-tools.db?mode=rwc` | SQLite path |
| `PORT` / `HOST` | `3210` / `0.0.0.0` | Listen address |
| `TLS_CERT` / `TLS_KEY` | — | Direct TLS; or set `BEHIND_TLS_PROXY=1` behind an HTTPS reverse proxy |
| `RP_ORIGIN` | the address the browser uses | Optional. Pins the only panel address accepted for passkeys, e.g. `https://pve.example.com` |
| `RP_ID` | the panel's domain | Optional. Passkey domain; must equal the panel's domain or a parent domain, e.g. `example.com` |
| `STATIC_DIR` | `static` | Web UI directory; only read by binaries built without the web UI (release binaries have it built in) |
| `DATA_DIR` | `data` | Runtime files (managed `known_hosts`) |
| `DEPLOY_MODE` | — | Set to `docker` by the Docker image: the in-app update is refused there (update by loading a new image) |
| `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` | — | Bootstrap admin on first boot (only when no admin exists); remove after creation |
| `UPDATE_GITHUB_REPO` | `MOSSDATA-NETWORK/PVE-Advanced-Tools` | Update source |
| `platform_public_url` (panel setting) | — | Node-reachable platform URL, required before pushing vmqos configs |
| `github_mirror_token` (panel setting) | — | GitHub token used when vmqos is a private repo; nodes then download the binary through the platform proxy (stored encrypted, masked in UI) |

### Passkey

Passkeys need the panel opened through a domain over HTTPS (or `http://localhost` on the same machine) — IP addresses and plain HTTP do not work. Behind a reverse proxy, the browser's `Origin` header must reach the backend unchanged (the provided nginx config does). Each passkey is bound to the exact address (scheme, domain, port) it was registered on — after changing that address, sign in with password + TOTP and register again, so keeping TOTP as a backup is recommended.

## Quick start

1. **Settings** → set `platform_public_url` (e.g. `https://panel.example.com`)
2. **Hosts** → add a PVE node (SSH credentials) → confirm the SSH fingerprint (TOFU)
3. Component tabs (**出网管控 / ARP 降噪 / 母机优化 / 带宽 QoS**) → install / configure per host; every action runs as an auditable, rollback-capable job (**任务** page)
4. **带宽 QoS**: issue node tokens → install vmqos → add per-VM rate policies → nodes pull their snapshot and start dynamic rate limiting; events appear in the QoS event stream
5. **告警与巡检**: configure Telegram / WeCom channels, tune inspection interval and alert rules

## Update & rollback

**Upgrading:** after upgrading to this version everyone is signed out once; accounts without TOTP or a passkey must bind one at the next sign-in. Panels installed from the first v0.0.1 build (since replaced by the current v0.0.1) cannot update themselves: reinstall once with Option A.

- **Panel**: Settings → check for updates → one-click update. The panel downloads the binary from the latest GitHub Release, checks it against the release's `SHA256SUMS`, swaps it (the web UI comes with it) and restarts the systemd service. The server must reach `api.github.com` and `github.com`. Behind your own reverse proxy, allow up to 15 minutes for `/api/version/update` (the provided nginx config does).
- **Docker**: back up the data volume, load the new image (Docker steps above), then run `docker compose up -d` again (or remove and re-create the container). The in-app update button refuses to run in Docker.
- **Rollback**: restore `<binary>.bak` and `<db>.bak` (both written next to the originals before every update), then restart the service. Docker: restore the volume backup and run the previous image tag.

## Security notes

- SSH host keys are pinned after explicit fingerprint confirmation; address changes invalidate the confirmation
- Credentials are encrypted with AES-256-GCM; decryption failure is fail-closed
- Node-facing API tokens are stored as hashes (verification) + AES-GCM ciphertext (provisioning); rotation overlaps until the new config is confirmed live
- vmqos downloads on nodes are verified against the release SHA256SUMS before installation
- In-app updates check the binary against the release's `SHA256SUMS`. This catches broken or incomplete downloads, but there is no separate signing key: anyone who can publish releases in this GitHub repository can ship an update, so protect access to the repository

## Attribution

Copyright © MOSSDATA. Maintained by **mossdata**.

Integrates components from: Noqjj (detection base), PVE-shell (ops script collection), vmqos (node bandwidth scheduler — used unmodified, via its snapshot API contract).

## License

Unless a LICENSE file states otherwise, all rights reserved by the repository owner. Contact MOSSDATA before commercial reuse.
