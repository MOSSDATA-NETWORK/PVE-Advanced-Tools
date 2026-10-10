# PVE Advanced Tools · PVE 母机一体化管控平台

[English](README.md) | **简体中文**

面向 VPS 运营方的一体化 **Proxmox VE** 母机管理平台：一个 Web 控制台统一管理多台 PVE 宿主机，
集「防滥用检测 + 网络管控 + 性能优化 + 带宽 QoS + 巡检告警」于一体，替代散落在各处的脚本。

- **后端**：Rust + Axum + SQLite（单二进制，前端内嵌）
- **前端**：Vue 3 + Vite
- **节点执行**：SSH 作业器（平台不在节点驻留新 agent）；节点侧常驻组件只有被管理的对象本身（vmqos 守护进程与各 systemd 服务）

## 功能

### 防滥用检测（Noqjj 底座）
- 全机 VM 的 guest-agent / 磁盘特征扫描，支持定时扫描与结果历史

### 网络管控
- **出网管控（netguard）**：按主机的端口/域名封堵，iptables 原子链切换，VMID 白名单，备份回滚
- **ARP 降噪（arpfilter）**：passive / static 双模式，单任务原子切换，灰度白名单与静态映射表下发

### 母机优化
- 一键初始化（no-subscription 换源、去订阅弹窗）
- 内核/sysctl/THP/KSM/IO 调度/ZFS ARC 优化，清单式备份，支持回滚

### 带宽 QoS（整合 vmqos）
- 平台实现 **vmqos 快照 API 契约（schema v2）**——vmqos 在节点零改动运行，向本平台拉取策略快照
- 按 VM 配置基础速率（国内/国际双数据源）、阶梯档位模板（节点级）、限速事件流、节点状态（fresh / degraded / stale）
- 每节点接入 token，支持重叠轮换（新配置生效后旧 token 才撤销）

### 平台基础能力
- **SSH 作业器**：任务包 HMAC-SHA256 签名、步骤检查点续跑、同主机串行、fail-open / fail-closed 分类失败策略、排队 TTL、重启对账、步骤级回滚
- **SSH 主机密钥指纹固定（TOFU）**：指纹确认流程 + 平台维护 known_hosts，确认后强制 `StrictHostKeyChecking=yes`
- **VM 稳定标识**：SMBIOS UUID 优先、node+VMID 兜底，自动重绑并留痕
- **巡检告警**：定时巡检（磁盘/内存/负载/VM 数/组件存活），Telegram 与企业微信通知，告警去重
- **审计日志**：敏感操作全部留痕可查
- **在线更新**：GitHub Releases 检查、SHA256SUMS + ed25519 签名校验（失败关闭）、原子替换、更新前自动备份 SQLite 与二进制、启动自检与 `.bak` 回滚
- **认证**：密码 + TOTP 两步验证 + passkey，登录限流，初始化仅限本机直连

## 环境要求

| 组件 | 要求 |
|---|---|
| 平台宿主机 | Linux（x86_64/aarch64）或 macOS；约 50 MB 内存 |
| 被管节点 | Proxmox VE 7 / 8 / 9，root SSH 可达 |
| 节点工具 | `curl`、`sha256sum`、`iptables`、`python3`（arpfilter）、`systemd` |

## 部署教程

### 方式 A —— 预编译二进制（推荐）

从 [Releases](https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases) 下载并校验：

```bash
curl -fSLO https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases/latest/download/pve-advanced-tools-linux-x86_64
curl -fSLO https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools/releases/latest/download/SHA256SUMS
grep pve-advanced-tools-linux-x86_64 SHA256SUMS | sha256sum -c -
chmod +x pve-advanced-tools-linux-x86_64
```

### 方式 B —— 源码构建

```bash
# 前端（产物内嵌进二进制静态目录）
cd frontend && npm install && npm run build   # 输出到 backend/static

# 后端
cd ../backend && cargo build --release        # target/release/pve-advanced-tools-backend
```

### 安装为系统服务

```bash
sudo bash deploy/install.sh [端口]   # 默认 3210
```

安装脚本会：
- 把二进制与前端资源复制到 `/opt/pve-advanced-tools`
- **生成并持久化 `MASTER_KEY`** 到 `/opt/pve-advanced-tools/env`（600 权限）——重装时复用
- 注册并启动 `pve-advanced-tools` systemd 服务

**创建管理员**（两种方式任选）：

1. **环境变量引导（推荐，适合纯外网服务器）**：启动前在服务配置中设置
   `INITIAL_ADMIN_USERNAME=admin` 与 `INITIAL_ADMIN_PASSWORD=<强密码>`（install.sh 可写入 `/opt/pve-advanced-tools/env`），
   首次启动自动建号；**创建成功后请移除这两个变量并重启**。
2. **SSH 隧道**：`ssh -L 3210:127.0.0.1:3210 root@服务器`，浏览器访问 `http://127.0.0.1:3210` 走页面初始化
  （网页初始化端点仅限本机直连，防止域名公布后他人抢建管理员）。

初始化完成后，日常访问走域名反代即可，无任何限制。

### 配置项（环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `MASTER_KEY` | 自动生成（打印一次） | **生产必填**。64 位 hex，用于加密已存凭据；丢失或变更后旧凭据无法解密（失败关闭） |
| `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` | — | 首次启动引导创建管理员（仅无管理员时生效）；创建成功后应移除 |
| `DATABASE_URL` | `sqlite:pve-advanced-tools.db?mode=rwc` | SQLite 路径 |
| `PORT` / `HOST` | `3210` / `0.0.0.0` | 监听地址 |
| `TLS_CERT` / `TLS_KEY` | — | 直接 TLS；或在 HTTPS 反代后设 `BEHIND_TLS_PROXY=1` |
| `STATIC_DIR` | `static` | 前端资源目录 |
| `DATA_DIR` | `data` | 运行时文件（平台维护的 known_hosts） |
| `UPDATE_SIGN_PUBKEY` | — | 更新验签公钥（ed25519 hex）。配置后发布必须带 `.sig`；未配置时拒绝在线更新（失败关闭） |
| `UPDATE_GITHUB_REPO` | `MOSSDATA-NETWORK/PVE-Advanced-Tools` | 更新来源仓库 |
| `platform_public_url`（面板设置） | — | 节点可达的平台地址，下发 vmqos 配置前必须配置 |

## 快速上手

1. **设置** → 配置 `platform_public_url`（如 `https://panel.example.com`）
2. **主机** → 添加 PVE 节点（SSH 凭据）→ 确认 SSH 指纹（TOFU）
3. 各组件页（**出网管控 / ARP 降噪 / 母机优化 / 带宽 QoS**）按主机安装与配置；所有动作都是可审计、可回滚的任务（见**任务**页）
4. **带宽 QoS**：签发节点 token → 安装 vmqos → 配置 VM 速率策略 → 节点拉取快照开始动态限速；限速事件见 QoS 事件流
5. **告警与巡检**：配置 Telegram / 企业微信通知渠道，调整巡检间隔与告警规则

## 更新与回滚

- **面板**：设置 → 检查更新 → 一键更新（SHA256SUMS + ed25519 签名强制校验）
- **回滚**：恢复同目录下的 `<二进制>.bak` 与 `<数据库>.bak`（每次更新前自动写入），重启服务即可

## 安全说明

- SSH 主机密钥在显式确认指纹后固定；地址变更自动失效需重新确认
- 凭据使用 AES-256-GCM 加密；解密失败按失败关闭处理
- 节点 API token 以哈希（校验）+ AES-GCM 密文（下发）双存储；轮换采用重叠期，新配置确认生效后才撤销旧 token
- 节点下载 vmqos 先校验发布 SHA256SUMS 再安装

## 署名

Copyright © MOSSDATA。由 **mossdata** 维护。

整合来源：Noqjj（检测底座）、PVE-shell（运维脚本集）、vmqos（节点带宽调度守护进程，零改动复用，经快照 API 契约接入）。
整合规划见 [大纲.md](大纲.md)，P3 设计决策见 [docs/P3-design-draft.md](docs/P3-design-draft.md)。

## 许可证

本仓库未附带 LICENSE 文件，默认保留所有权利。商用前请联系 MOSSDATA。
