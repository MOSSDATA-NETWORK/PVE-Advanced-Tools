<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { resultsApi, hostsApi } from '../api'
import { formatTime } from '../time'
import axios from 'axios'

const results = ref<any[]>([])
const hosts = ref<any[]>([])
const loading = ref(true)
const total = ref(0)
const pageSize = ref(20)
const currentPage = ref(1)
const filterHost = ref<number | null>(null)
const filterStatus = ref('')
const needsDiskTotal = ref(0)
const scanningVmid = ref<string | null>(null)
const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))
const hostMap = computed(() => {
  const map: Record<number, string> = {}
  hosts.value.forEach((h: any) => { map[h.id] = h.name })
  return map
})
const pageOptions = [10, 20, 50, 100]

onMounted(async () => {
  try {
    const h = await hostsApi.list()
    if (h.ok) hosts.value = h.data
  } catch {}
  await loadResults()
  loadNeedsDiskCount()
})

async function loadNeedsDiskCount() {
  try {
    const res = await resultsApi.list({ status: 'needs_disk_scan', limit: 1 })
    if (res.ok) needsDiskTotal.value = res.total || 0
  } catch {}
}

async function loadResults() {
  loading.value = true
  try {
    const offset = (currentPage.value - 1) * pageSize.value
    const params: any = { limit: pageSize.value, offset }
    if (filterHost.value) params.host_id = filterHost.value
    if (filterStatus.value) params.status = filterStatus.value
    const res = await resultsApi.list(params)
    if (res.ok) {
      results.value = res.data
      total.value = res.total || 0
    }
  } finally {
    loading.value = false
  }
}

function changePage(page: number) {
  if (page < 1 || page > totalPages.value) return
  currentPage.value = page
  loadResults()
}

function changePageSize(size: number) {
  pageSize.value = size
  currentPage.value = 1
  loadResults()
}

function onFilterChange() {
  currentPage.value = 1
  loadResults()
}

function statusBadge(s: string) {
  const m: Record<string, string> = {
    detected: 'badge-detected', confirmed: 'badge-confirmed',
    cleaned: 'badge-cleaned', clean: 'badge-clean',
    needs_disk_scan: 'badge-confirmed', error: 'badge-detected',
  }
  return m[s] || 'badge-unknown'
}

function statusLabel(s: string) {
  const m: Record<string, string> = {
    detected: '新发现', confirmed: '持续存在', cleaned: '已清除', clean: '正常',
    needs_disk_scan: '待检测', error: '检测失败',
  }
  return m[s] || s
}

// 证据代码 → 中文说明（与后端 chicken-check.sh 的输出一一对应）
const EVIDENCE_FIXED: Record<string, { label: string; desc: string }> = {
  incus_dir: { label: 'Incus 切鸡目录', desc: '存在 /opt/incus 目录——安装了 Incus 容器系统，是切小鸡的核心组件' },
  incus_data: { label: 'Incus 数据目录', desc: '存在 /var/lib/incus——Incus 已初始化并实际使用过' },
  incushlii_agent: { label: 'incushlii 管理程序', desc: '存在 /usr/local/bin/incushlii-agent——shlii 平台的切鸡管理程序' },
  lxd: { label: 'LXD 运营痕迹', desc: 'LXD 已初始化（lxd.db / database / 非空容器或磁盘）——在用 LXD 分割实例' },
  nodehatch_proj: { label: 'NodeHatch 面板项目', desc: 'Incus 中存在 NodeHatch 切鸡面板创建的项目' },
  nodehatch_cert: { label: 'NodeHatch 面板证书', desc: 'Incus 信任证书中存在 NodeHatch 面板的证书' },
  zabbly_incus: { label: 'zabbly 软件源', desc: '配置了 zabbly 的 Incus 安装源——专门用于装 Incus 切鸡' },
  api_8443: { label: 'Incus 管理端口', desc: 'incusd 进程正在监听 8443 管理端口' },
  vm_stopped: { label: '已关机', desc: '检测时该 VM 处于关机状态，未执行检测' },
}

interface EvidenceItem { raw: string; label: string; desc: string; items?: string[] }

// 把后端证据串转成中文条目列表。
// 格式: "svc:8 hist:1 net:1##svc=名1|名2##hist=命令##net=连接"
// '##' 后是明细段（检测脚本 v6 起上报），旧数据无明细段则只显示数量
function evidenceItems(e: string | null | undefined): EvidenceItem[] {
  const parts = (e || '').split('##')
  const head = (parts.shift() || '').trim()
  if (!head) return []
  const detailMap: Record<string, string[]> = {}
  for (const sec of parts) {
    const i = sec.indexOf('=')
    if (i <= 0) continue
    const key = sec.slice(0, i)
    const vals = sec.slice(i + 1).split(',').map(s => s.trim()).filter(Boolean)
    detailMap[key] = [...(detailMap[key] || []), ...vals]
  }
  return head.split(/\s+/).map((t): EvidenceItem => {
    const m = t.match(/^(svc|hist|net):(\d+)$/)
    if (m) {
      const n = Number(m[2])
      const items = detailMap[m[1]]
      if (m[1] === 'svc') return { raw: t, label: `可疑系统服务 × ${n}`, desc: `在 /etc/systemd/system/ 下发现 ${n} 个名称含 incus / shlii / nodehatch 的服务文件——安装了切鸡或机场相关服务`, items }
      if (m[1] === 'hist') return { raw: t, label: `可疑命令历史 × ${n}`, desc: `bash 历史中有 ${n} 条与 shlii.io / incushlii / nodehatch 相关的命令——执行过安装或管理操作`, items }
      return { raw: t, label: `可疑网络连接 × ${n}`, desc: `当前有 ${n} 条由可疑进程发起的网络连接——切鸡 / 机场程序正在联网运行`, items }
    }
    const fixed = EVIDENCE_FIXED[t]
    return fixed ? { raw: t, ...fixed } : { raw: t, label: t, desc: '' }
  })
}

function methodLabel(m: string | null | undefined) {
  const map: Record<string, string> = { ga: 'GA 内部检测', disk: '磁盘扫描' }
  return map[m || ''] || m || '-'
}

const detailRow = ref<any>(null)

const batchScanning = ref(false)
const batchProgress = ref('')
const diskResult = ref<{ ok: boolean; text: string } | null>(null)
const confirmBox = ref<{ title: string; message: string; confirmText: string; action: () => void } | null>(null)

function askConfirm(title: string, message: string, confirmText: string, action: () => void) {
  confirmBox.value = { title, message, confirmText, action }
}

function runConfirm() {
  const action = confirmBox.value?.action
  confirmBox.value = null
  action?.()
}

async function batchDiskScan() {
  let targets: any[] = []
  try {
    const res = await resultsApi.list({ status: 'needs_disk_scan', limit: 100 })
    if (res.ok) targets = res.data || []
  } catch {}
  if (targets.length === 0) return
  askConfirm('批量磁盘扫描',
    `将对 ${targets.length} 台待检测 VM 逐台执行磁盘扫描。\n每台约几秒到几分钟，期间请勿关闭页面。`,
    '开始扫描',
    async () => {
      batchScanning.value = true
      diskResult.value = null
      let ok = 0
      let fail = 0
      for (let i = 0; i < targets.length; i++) {
        const t = targets[i]
        batchProgress.value = `正在扫描 VM ${t.vmid}（${i + 1}/${targets.length}）`
        try {
          await axios.post(`/api/hosts/${t.host_id}/scan-vm`, { vmid: t.vmid })
          ok++
        } catch {
          fail++
        }
      }
      batchScanning.value = false
      batchProgress.value = ''
      diskResult.value = { ok: fail === 0, text: fail === 0 ? `批量磁盘扫描完成：成功 ${ok} 台` : `批量磁盘扫描完成：成功 ${ok} 台，失败 ${fail} 台` }
      await loadResults()
      loadNeedsDiskCount()
    })
}

async function triggerDiskScan(vmid: string) {
  const result = results.value.find(r => r.vmid === vmid)
  const hostId = result?.host_id
  askConfirm('磁盘扫描',
    `确定对 VM ${vmid} 执行磁盘扫描？\n将只读挂载磁盘镜像逐项检查切鸡特征，约几秒到几分钟。`,
    '开始扫描',
    async () => {
      scanningVmid.value = vmid
      diskResult.value = null
      try {
        if (!hostId) {
          diskResult.value = { ok: false, text: '未找到主机信息' }
          return
        }
        const res = await axios.post(`/api/hosts/${hostId}/scan-vm`, { vmid })
        if (res.data.ok) {
          diskResult.value = { ok: true, text: `VM ${vmid} 磁盘扫描完成，结果已更新` }
        } else {
          diskResult.value = { ok: false, text: res.data.error || '扫描失败' }
        }
      } catch (e: any) {
        diskResult.value = { ok: false, text: e.response?.data?.error || '请求失败' }
      } finally {
        scanningVmid.value = null
        await loadResults()
        loadNeedsDiskCount()
      }
    })
}

function getPageNumbers() {
  const pages: (number | string)[] = []
  const p = currentPage.value
  const t = totalPages.value
  if (t <= 7) {
    for (let i = 1; i <= t; i++) pages.push(i)
  } else {
    pages.push(1)
    if (p > 3) pages.push('...')
    for (let i = Math.max(2, p - 1); i <= Math.min(t - 1, p + 1); i++) pages.push(i)
    if (p < t - 2) pages.push('...')
    pages.push(t)
  }
  return pages
}
</script>

<template>
  <div>
    <div class="page-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
      <div>
        <h1 class="page-title">检测结果</h1>
        <p class="page-subtitle">查看所有 VM 的检测状态</p>
      </div>
      <div style="display: flex; gap: 12px;">
        <select class="form-input" style="width: 160px;" v-model="filterHost" @change="onFilterChange">
          <option :value="null">全部主机</option>
          <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.name }}</option>
        </select>
        <select class="form-input" style="width: 140px;" v-model="filterStatus" @change="onFilterChange">
          <option value="">全部状态</option>
          <option value="detected">新发现</option>
          <option value="confirmed">持续存在</option>
          <option value="cleaned">已清除</option>
          <option value="needs_disk_scan">待检测</option>
          <option value="error">检测失败</option>
        </select>
      </div>
    </div>

    <!-- 无 Guest Agent 提示条 -->
    <div v-if="needsDiskTotal > 0" class="card" style="margin-bottom: 16px; background: rgba(255,149,0,0.04); border: 1px solid rgba(255,149,0,0.15);">
      <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
        <span style="font-size: 24px;">💾</span>
        <div style="flex: 1; min-width: 200px;">
          <div style="font-weight: 600;">{{ needsDiskTotal }} 个 VM 未安装 Guest Agent</div>
          <div style="font-size: 13px; color: var(--text-secondary); margin-top: 2px;">
            {{ batchScanning ? batchProgress : '这些 VM 无法通过 GA 检测，可逐台或批量执行磁盘扫描' }}
          </div>
        </div>
        <button class="btn btn-primary" @click="batchDiskScan" :disabled="batchScanning">
          {{ batchScanning ? '批量扫描中...' : '批量磁盘扫描' }}
        </button>
      </div>
    </div>

    <!-- 磁盘扫描结果条 -->
    <div v-if="diskResult" style="margin-bottom: 16px; display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-radius: 12px;"
      :style="{ background: diskResult.ok ? 'rgba(52,199,89,0.08)' : 'rgba(255,59,48,0.08)', border: '1px solid ' + (diskResult.ok ? 'rgba(52,199,89,0.2)' : 'rgba(255,59,48,0.2)') }">
      <span style="font-size: 18px;">{{ diskResult.ok ? '✅' : '❌' }}</span>
      <span style="font-size: 14px; flex: 1;">{{ diskResult.text }}</span>
      <button class="btn btn-sm btn-secondary" @click="diskResult = null">关闭</button>
    </div>

    <div class="card">
      <div v-if="loading" style="text-align: center; padding: 40px;">
        <div class="spinner" style="margin: 0 auto;"></div>
      </div>
      <div v-else-if="results.length === 0" class="empty-state">
        <p>暂无检测结果</p>
      </div>
      <div v-else>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>VM ID</th>
                <th>主机</th>
                <th>状态</th>
                <th>检测方式</th>
                <th>证据</th>
                <th>首次发现</th>
                <th>最后检测</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in results" :key="r.id">
                <td style="font-weight: 600;">VM {{ r.vmid }}</td>
                <td>{{ hostMap[r.host_id] || `#${r.host_id}` }}</td>
                <td><span :class="['badge', statusBadge(r.status)]">{{ statusLabel(r.status) }}</span></td>
                <td><code style="font-size: 12px;">{{ r.method || '-' }}</code></td>
                <td style="font-size: 13px; max-width: 300px;">
                  <div v-if="evidenceItems(r.evidence).length" style="display: flex; flex-wrap: wrap; gap: 6px; align-items: center;">
                    <span v-for="t in evidenceItems(r.evidence)" :key="t.raw" class="evidence-tag">{{ t.label }}</span>
                    <button class="btn btn-sm btn-secondary" @click="detailRow = r">详情</button>
                  </div>
                  <span v-else style="color: var(--text-tertiary);">-</span>
                </td>
                <td style="font-size: 13px; color: var(--text-secondary);">{{ formatTime(r.first_seen) }}</td>
                <td style="font-size: 13px; color: var(--text-secondary);">{{ formatTime(r.last_seen) }}</td>
                <td>
                  <button v-if="r.status === 'needs_disk_scan'"
                    class="btn btn-sm btn-secondary"
                    @click="triggerDiskScan(r.vmid)"
                    :disabled="scanningVmid === r.vmid">
                    {{ scanningVmid === r.vmid ? '扫描中...' : '磁盘扫描' }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 分页栏 -->
        <div class="pagination">
          <div class="pagination-info">
            共 {{ total }} 条，第 {{ currentPage }}/{{ totalPages }} 页
          </div>
          <div class="pagination-controls">
            <select class="page-size-select" :value="pageSize" @change="changePageSize(Number(($event.target as HTMLSelectElement).value))">
              <option v-for="opt in pageOptions" :key="opt" :value="opt">{{ opt }} 条/页</option>
            </select>
            <div class="page-buttons">
              <button class="page-btn" :disabled="currentPage <= 1" @click="changePage(1)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/></svg>
              </button>
              <button class="page-btn" :disabled="currentPage <= 1" @click="changePage(currentPage - 1)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="15 18 9 12 15 6"/></svg>
              </button>
              <template v-for="(p, i) in getPageNumbers()" :key="i">
                <span v-if="p === '...'" class="page-ellipsis">...</span>
                <button v-else class="page-btn" :class="{ active: p === currentPage }" @click="changePage(Number(p))">
                  {{ p }}
                </button>
              </template>
              <button class="page-btn" :disabled="currentPage >= totalPages" @click="changePage(currentPage + 1)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="9 18 15 12 9 6"/></svg>
              </button>
              <button class="page-btn" :disabled="currentPage >= totalPages" @click="changePage(totalPages)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="13 17 18 12 13 7"/><polyline points="6 17 11 12 6 7"/></svg>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 确认弹窗 -->
    <div v-if="confirmBox" class="modal-overlay" @click.self="confirmBox = null">
      <div class="modal" style="max-width: 440px;">
        <div class="modal-header">{{ confirmBox.title }}</div>
        <div class="modal-body">
          <p style="font-size: 14px; color: var(--text-secondary); line-height: 1.8; margin: 0; white-space: pre-line;">{{ confirmBox.message }}</p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="confirmBox = null">取消</button>
          <button class="btn btn-primary" @click="runConfirm">{{ confirmBox.confirmText }}</button>
        </div>
      </div>
    </div>

    <!-- 检测详情弹窗 -->
    <div v-if="detailRow" class="modal-overlay" @click.self="detailRow = null">
      <div class="modal" style="max-width: 560px;">
        <div class="modal-header">VM {{ detailRow.vmid }} 检测详情</div>
        <div class="modal-body">
          <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 14px; font-size: 13px; color: var(--text-secondary);">
            <span>状态：<b style="color: var(--text);">{{ statusLabel(detailRow.status) }}</b></span>
            <span>检测方式：{{ methodLabel(detailRow.method) }}</span>
            <span>主机：{{ hostMap[detailRow.host_id] || `#${detailRow.host_id}` }}</span>
          </div>
          <div v-if="evidenceItems(detailRow.evidence).length">
            <div v-for="t in evidenceItems(detailRow.evidence)" :key="t.raw"
              style="padding: 10px 14px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 8px;">
              <div style="font-weight: 600; font-size: 14px;">{{ t.label }}</div>
              <div style="font-size: 13px; color: var(--text-secondary); margin-top: 3px; line-height: 1.6;">
                {{ t.desc || ('原始证据：' + t.raw) }}
              </div>
              <ul v-if="t.items && t.items.length" style="margin: 6px 0 0; padding-left: 18px;">
                <li v-for="(it, i) in t.items" :key="i"
                  style="font-size: 12.5px; color: var(--text-secondary); line-height: 1.7; word-break: break-all;">{{ it }}</li>
              </ul>
            </div>
          </div>
          <p v-else style="color: var(--text-secondary); font-size: 14px; margin: 0;">没有命中任何切鸡特征。</p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="detailRow = null">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.evidence-tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 12px;
  background: rgba(255, 59, 48, 0.08);
  color: var(--red);
  border: 1px solid rgba(255, 59, 48, 0.2);
  white-space: nowrap;
}
.pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0 4px;
  flex-wrap: wrap;
  gap: 12px;
}
.pagination-info { font-size: 13px; color: var(--text-secondary); }
.pagination-controls { display: flex; align-items: center; gap: 12px; }
.page-size-select {
  padding: 6px 10px; border: 1px solid var(--border); border-radius: 8px;
  font-size: 13px; background: var(--bg-secondary); color: var(--text);
  cursor: pointer; font-family: var(--font);
}
.page-buttons { display: flex; align-items: center; gap: 4px; }
.page-btn {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 32px; height: 32px; padding: 0 6px;
  border: 1px solid var(--border); border-radius: 8px;
  background: var(--bg-secondary); color: var(--text);
  font-size: 13px; font-weight: 500; cursor: pointer;
  transition: all 0.15s; font-family: var(--font);
}
.page-btn:hover:not(:disabled):not(.active) { background: rgba(0,0,0,0.04); }
.page-btn.active { background: var(--accent); color: white; border-color: var(--accent); }
.page-btn:disabled { opacity: 0.35; cursor: not-allowed; }
.page-ellipsis { padding: 0 4px; color: var(--text-tertiary); font-size: 13px; }
@media (max-width: 768px) {
  .pagination { flex-direction: column; align-items: stretch; }
  .pagination-controls { justify-content: space-between; }
}
</style>
