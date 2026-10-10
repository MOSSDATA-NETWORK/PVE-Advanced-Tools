<script setup lang="ts">
import { ref, onMounted , watch } from 'vue'
import { useRoute } from 'vue-router'
import { hostsApi } from '../api'
import axios from 'axios'

const route = useRoute()
const tab = ref<string>((route.query.tab as string) || 'init')
watch(() => route.query.tab, t => { tab.value = (t as string) || 'init' })

const hosts = ref<any[]>([])
const components = ref<Record<string, any>>({})
const statusMap = ref<Record<number, any>>({})
const loading = ref(true)
const notice = ref<{ ok: boolean; text: string } | null>(null)
const busy = ref<string | null>(null)

onMounted(loadAll)

async function loadAll() {
  loading.value = true
  try {
    const h = await hostsApi.list()
    if (h.ok) hosts.value = h.data
    // 逐台读最近一次状态任务结果
    for (const host of hosts.value) {
      try {
        const res = await axios.get(`/api/optimize/status/${host.id}`)
        if (res.data.ok && res.data.output) {
          statusMap.value[host.id] = res.data
        }
      } catch {}
    }
    try {
      const st = await axios.get('/api/netguard/status')
      if (st.data.ok) components.value = st.data.components
    } catch {}
  } finally {
    loading.value = false
  }
}

function showNotice(ok: boolean, text: string) {
  notice.value = { ok, text }
  setTimeout(() => (notice.value = null), 8000)
}

async function run(hostId: number, action: string, label: string) {
  busy.value = `${hostId}:${action}`
  try {
    const res = await axios.post(`/api/optimize/${action}/${hostId}`, {})
    showNotice(res.data.ok, res.data.ok ? `${label} 任务已下发（#${res.data.job_id}），详见「任务中心」` : res.data.error)
  } catch (e: any) {
    showNotice(false, e.response?.data?.error || '请求失败')
  } finally {
    busy.value = null
  }
}

async function batchRun(action: string, label: string) {
  if (!confirm(`将对所有已确认指纹的主机执行「${label}」，继续？`)) return
  busy.value = 'batch'
  try {
    const res = await axios.post('/api/optimize/batch', { action })
    showNotice(res.data.ok, res.data.ok ? `已创建 ${res.data.jobs.length} 个任务` : res.data.error)
  } finally {
    busy.value = null
  }
}

async function runUpgrade(hostId: number) {
  if (!confirm('系统更新（dist-upgrade）不可回滚，确认执行？')) return
  run(hostId, 'upgrade', '系统更新')
}

// 参数优化：可选择优化项（与后端 OPTIMIZE_ITEMS / 脚本 --only 白名单一致）
const OPT_ITEMS = [
  { id: 'ulimit', label: '文件句柄限制 (ulimit)' },
  { id: 'systemd_limits', label: 'systemd 默认限制' },
  { id: 'journald', label: 'journald 日志限额' },
  { id: 'sysctl', label: '内核参数 (sysctl：网络/内存/连接跟踪)' },
  { id: 'bbr', label: 'BBR 拥塞控制' },
  { id: 'thp', label: '透明大页 (THP)' },
  { id: 'cpu_governor', label: 'CPU 调度策略 (performance)' },
  { id: 'ksm', label: 'KSM 内存去重' },
  { id: 'io_scheduler', label: 'IO 调度器' },
  { id: 'dmesg', label: 'dmesg 权限放开' },
  { id: 'zfs_arc', label: 'ZFS ARC 缓存上限' },
  { id: 'timezone', label: '时区与 NTP' },
]
const tuneHost = ref<any | null>(null)
const tuneBatch = ref(false)
const tuneSel = ref<string[]>([])

function openTune(h: any) {
  tuneBatch.value = false
  tuneHost.value = h
  tuneSel.value = OPT_ITEMS.map(i => i.id)
}

function openBatchTune() {
  tuneBatch.value = true
  tuneHost.value = { name: '全部已确认指纹的主机' }
  tuneSel.value = OPT_ITEMS.map(i => i.id)
}

async function confirmTune() {
  const h = tuneHost.value
  if (!h) return
  if (!tuneSel.value.length) { showNotice(false, '至少选择一项优化项'); return }
  const items = [...tuneSel.value]
  const isBatch = tuneBatch.value
  tuneHost.value = null
  busy.value = isBatch ? 'batch' : `${h.id}:tune`
  try {
    const res = isBatch
      ? await axios.post('/api/optimize/batch', { action: 'tune', items })
      : await axios.post(`/api/optimize/tune/${h.id}`, { items })
    showNotice(res.data.ok, res.data.ok
      ? (isBatch
        ? `批量优化已创建 ${res.data.jobs.length} 个任务（${items.length} 项/台）`
        : `参数优化任务已下发（#${res.data.job_id}，${items.length} 项），详见「任务中心」`)
      : res.data.error)
  } catch (e: any) {
    showNotice(false, e.response?.data?.error || '请求失败')
  } finally {
    busy.value = null
  }
}

async function rollback(hostId: number, component: string) {
  if (!confirm(`确定回滚 ${component === 'nosub' ? '一键初始化' : '参数优化'}？将恢复到上次备份。`)) return
  busy.value = `${hostId}:rollback`
  try {
    const res = await axios.post(`/api/optimize/rollback/${hostId}`, { component })
    showNotice(res.data.ok, res.data.ok ? `回滚任务已下发（#${res.data.job_id}）` : res.data.error)
  } finally {
    busy.value = null
  }
}

async function refreshStatus(hostId: number) {
  busy.value = `${hostId}:status`
  try {
    const res = await axios.post(`/api/optimize/status/${hostId}`)
    if (!res.data.ok) {
      showNotice(false, res.data.error)
      return
    }
    showNotice(true, '状态回采中，完成后自动刷新')
    // 轮询任务完成（最多 60 秒），完成后重新拉取状态
    const jobId = res.data.job_id
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 3000))
      try {
        const j = await axios.get(`/api/jobs/${jobId}`)
        if (j.data.ok && ['succeeded', 'failed', 'rolled_back'].includes(j.data.data.job.status)) {
          break
        }
      } catch { break }
    }
    const st = await axios.get(`/api/optimize/status/${hostId}`)
    if (st.data.ok && st.data.output) statusMap.value[hostId] = st.data
  } finally {
    busy.value = null
  }
}

function compInstalled(hostId: number, name: string) {
  return !!components.value[String(hostId)]?.[name]
}

function parseStatus(hostId: number) {
  const raw = statusMap.value[hostId]?.output
  if (!raw) return null
  try { return JSON.parse(raw.trim().split('\n').pop() || '') } catch { return null }
}
</script>

<template>
  <div>
    <div class="page-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
      <div>
        <h1 class="page-title">母机优化</h1>
        <p class="page-subtitle">一键初始化（换源/去弹窗）与内核参数自适应优化，所有改动支持备份回滚</p>
      </div>
      <div style="display: flex; gap: 8px;">
        <button class="btn btn-secondary" @click="batchRun('init', '一键初始化')" :disabled="busy !== null">批量初始化</button>
        <button class="btn btn-secondary" @click="openBatchTune" :disabled="busy !== null">批量优化</button>
      </div>
    </div>

    <div v-if="notice" style="margin-bottom: 16px; padding: 12px 16px; border-radius: 12px;"
      :style="{ background: notice.ok ? 'rgba(52,199,89,0.08)' : 'rgba(255,59,48,0.08)', border: '1px solid ' + (notice.ok ? 'rgba(52,199,89,0.2)' : 'rgba(255,59,48,0.2)') }">
      <span style="font-size: 14px;">{{ notice.text }}</span>
    </div>

    <div class="card" id="init">
      <div v-if="loading" style="text-align: center; padding: 40px;"><div class="spinner" style="margin: 0 auto;"></div></div>
      <div v-else class="table-container">
        <table>
          <thead><tr><th>主机</th><th>PVE 版本</th><th>初始化</th><th>参数优化</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="h in hosts" :key="h.id">
              <td style="font-weight: 600;">{{ h.name }}</td>
              <td style="font-size: 12px; color: var(--text-secondary);">{{ h.pve_version?.split(' ')[0] || '-' }}</td>
              <td><span :class="['badge', compInstalled(h.id, 'nosub') ? 'badge-online' : 'badge-unknown']">{{ compInstalled(h.id, 'nosub') ? '已初始化' : '未初始化' }}</span></td>
              <td><span :class="['badge', compInstalled(h.id, 'optimize') ? 'badge-online' : 'badge-unknown']">{{ compInstalled(h.id, 'optimize') ? '已优化' : '未优化' }}</span></td>
              <td>
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                  <button v-if="tab === 'init'" class="btn btn-sm btn-primary" @click="run(h.id, 'init', '一键初始化')" :disabled="busy !== null">初始化</button>
                  <button v-if="tab === 'tune'" class="btn btn-sm btn-primary" @click="openTune(h)" :disabled="busy !== null">参数优化</button>
                  <button v-if="tab === 'init'" class="btn btn-sm btn-secondary" @click="runUpgrade(h.id)" :disabled="busy !== null" title="dist-upgrade，不可回滚">系统更新</button>
                  <button v-if="tab === 'tune'" class="btn btn-sm btn-secondary" @click="refreshStatus(h.id)" :disabled="busy !== null">状态回采</button>
                  <button v-if="tab === 'rollback' && compInstalled(h.id, 'nosub')" class="btn btn-sm btn-danger" @click="rollback(h.id, 'nosub')" :disabled="busy !== null">回滚初始化</button>
                  <button v-if="tab === 'rollback' && compInstalled(h.id, 'optimize')" class="btn btn-sm btn-danger" @click="rollback(h.id, 'optimize')" :disabled="busy !== null">回滚优化</button>
                </div>
                <div v-if="parseStatus(h.id)" style="font-size: 12px; color: var(--text-tertiary); margin-top: 6px;">
                  备份：nosub [{{ parseStatus(h.id).nosub_backups || '无' }}] optimize [{{ parseStatus(h.id).optimize_backups || '无' }}]
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 参数优化：选择优化项 -->
    <div v-if="tuneHost" class="modal-overlay" @click.self="tuneHost = null">
      <div class="modal" style="max-width: 480px;">
        <div class="modal-header">{{ tuneHost.name }} · 选择优化项{{ tuneBatch ? '（对每台主机生效）' : '' }}</div>
        <div class="modal-body">
          <div style="display: flex; gap: 12px; margin-bottom: 10px; font-size: 13px;">
            <a style="cursor: pointer; color: var(--accent);" @click="tuneSel = OPT_ITEMS.map(i => i.id)">全选</a>
            <a style="cursor: pointer; color: var(--text-secondary);" @click="tuneSel = []">清空</a>
            <span style="color: var(--text-tertiary);">已选 {{ tuneSel.length }}/{{ OPT_ITEMS.length }}</span>
          </div>
          <label v-for="it in OPT_ITEMS" :key="it.id" style="display: flex; align-items: center; gap: 8px; padding: 6px 0; font-size: 14px; cursor: pointer;">
            <input type="checkbox" :value="it.id" v-model="tuneSel" />
            {{ it.label }}
          </label>
          <p style="font-size: 12px; color: var(--text-tertiary); margin-top: 12px;">执行前自动备份全部相关配置，可在「回滚中心」一键恢复到上次备份。</p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="tuneHost = null">取消</button>
          <button class="btn btn-primary" @click="confirmTune" :disabled="!tuneSel.length">开始优化（{{ tuneSel.length }} 项）</button>
        </div>
      </div>
    </div>
  </div>
</template>
