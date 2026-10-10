# P3 带宽 QoS 设计（已冻结 2026-10-10）

状态：管理层双签一致（Claude + Codex/gpt-5.6-luna），范围偏差经用户拍板（模板降为节点级）。

基线：vmqos v0.0.6（~/Desktop/vmqos，契约 docs/vmqos-database-api-contract.md schema v2）。vmqos 零改动接入。

## 1. 范围

平台实现 vmqos 实调的 4 类端点 + 面板管理 + 节点组件管理（安装/配置/卸载）。

## 2. 数据表（005_p3.sql 草案）

- `clusters(id, name)`：契约要求 clusters 非空；hosts 增加 `cluster_id` 默认 1（种子「默认集群」）。
- `qos_templates(id, name, config_json, builtin, created_at)`：阶梯模板，存 [stages] 段结构化 JSON（high_usage_ratio / limits / raise_rules / recover_rules / peak）。
- `qos_policies(id, host_id, vm_uuid NULL, vmid, origin TEXT CHECK origin IN ('domestic','international'), template_id NULL, standalone_mbps NULL, net2_mbps NULL, enabled, UNIQUE(host_id, vmid, origin))`。
- `qos_tokens(host_id, purpose TEXT CHECK purpose IN ('snapshot','report','intl'), token_hash, token_enc, status, created_at, rotated_at, last_used_at, PRIMARY KEY(host_id, purpose, status))`：哈希校验 + AES-GCM 密文下发；双 token 重叠轮换。
- `qos_events(id, host_id, origin, vmid, stage, limit_mbps, dedup_hash, reported_at)`：内容哈希 + 时间窗去重（无序号，无法严格一次）。
- `qos_vm_state(host_id, vmid, origin, current_stage, current_limit, updated_at, UNIQUE(host_id, vmid, origin))`：支撑 stage 核验端点。
- `qos_node_status(host_id PK, last_snapshot_at, last_report_at, last_error)`：节点状态证据。
- `qos_snapshots(id, host_id, snapshot_id, pulled_at, complete, raw_json)`：已下发快照归档（审计/排障）。

## 3. 端点（节点面，独立于管理员会话鉴权）

- `GET /api/v1/vmqos/snapshot?node_ip=`：Bearer token → 定位主机；node_ip 须等于主机已确认管理地址（或在显式允许地址表内）。按主机 enabled 策略生成 schema v2 双源快照；国际源无策略时 `status=disabled + services=[] + counts.services=0`。ports 含 net0（+可选 net2），mac 暂 null（平台未采 MAC）。回写 last_snapshot_at。
- `POST /api/v1/vmqos/qos/?r=api/report`：X-API-Token → 主机（payload host_ip 复核）。事件落库：dedup_hash = H(source, host, vmid, stage, limit_mbps)，120s 窗内同哈希只存一次（仍回 200 {ok:true}）。更新 qos_vm_state 与 last_report_at。
- `GET /api/v1/vmqos/qos/?r=api/stage&vmid&host_ip`：state 存在且 stage>0 → 200 {ok:true, stage}；stage=0 或无记录 → 404 {ok:false}。
- 国际站：`POST /api/v1/vmqos/intl/report`（payload 含 cluster_id）；`GET /api/v1/vmqos/intl/stage?cluster_id&vmid` → {ok:true, active: stage>0, stage}。
- 错误形状按契约 §5：{error:{code,message,retryable,request_id}}；401 UNAUTHORIZED / 403 NODE_FORBIDDEN。日志不落 token。

## 4. 节点状态推断

vmqos 无心跳端点：fresh = 最近快照拉取在 2× 刷新间隔内；degraded = 快照在拉但上报/核验失败或单源异常；stale = 超阈值无快照。状态变化进告警引擎。面板上标注「推断值」。

## 5. 作业器任务（复用既有框架）

- `qos.install`：Releases 元数据 + SHA256SUMS 校验 → 下载 → 备份旧件 → 原子安装 → 渲染 config.toml（api url/token、report url/token、模板 [stages]）→ `vmqos --check-config` → systemd 启动 → 快照拉取验证；失败回滚二进制+配置+服务。
- `qos.config_apply`：模板校验（阈值单调、比例 0-1、默认值齐全）→ 版本化渲染 → 原子替换 → 重启；记录模板版本。
- `qos.uninstall`：停服务 → 删配置/二进制 → 保留审计与快照归档；失败不得标记已卸载。
- token 轮换：发新 token → 下发配置 → 验证 → 撤销旧 token。

## 6. 已知偏差（需用户确认）

1. **大纲「多模板按 VM/分组分配」零改动下不可实现**：vmqos [stages] 为节点全局单份。提案：模板节点级生效（每节点一个活跃模板），VM 级自定义限 initial_mbps / 独立上下限。→ 待 Codex 对质后上报用户。
2. **事件无单调序号**：vmqos 上报载荷无 seq，只能内容哈希+时间窗近似去重，无法严格一次。
3. **degraded/stale 为推断值**：vmqos 不上报自身降级状态。
4. **MAC 不落快照**：平台未采 VM MAC，ports.mac 暂为 null（契约允许）。

## 7. 交叉评审结论（已收敛）

- 去掉平台直设 qm rate 的 VM 配速 job（与 vmqos reconcile 竞争）：平台只通过快照 initial_mbps 表达限速，rate 归 vmqos 管。
- 「多模板按 VM/分组分配」确认零改动不可实现 → 节点级模板（用户已拍板）。
- clusters 表保留，hosts.cluster_id NOT NULL 回填默认集群；主机创建 API 带 cluster_id（缺省 1）。
- 契约修正：complete=false 为建议性（按源缓存降级）；跨源合并 fresh 优先/同新鲜度国内优先；initial_mbps=0 = 保留状态跳过限速。
