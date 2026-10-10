<script setup lang="ts">
import { ref, onMounted, computed , watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { arpApi, hostsApi, arpStatsApi, jobsApi } from '../api'

const route = useRoute()
const router = useRouter()
const tab = ref<string>((route.query.tab as string) || 'mode')
watch(() => route.query.tab, t => { if (t) tab.value = t as string })
function setTab(t: string) { router.replace({ query: { tab: t } }) }

const hosts = ref<any[]>([])
const modes = ref<Record<number, string>>({})
const loading = ref(true)
const statsHost = ref<number | null>(null)
const statsRows = ref<any[]>([])
const statsLoading = ref(false)
const notice = ref<{ ok: boolean; text: string } | null>(null)
const detailHost = ref<number | null>(null)
const whitelist = ref<any[]>([])
const maps = ref<any[]>([])
const newWlVmid = ref('')
const newMap = ref({ vmid: '', nic: 0, ip: '' })
const importText = ref('')

const hostMap = computed(() => {
  const m: Record<number, string> = {}
  hosts.value.forEach((h: any) => { m[h.id] = h.name })
  return m
})

onMounted(loadAll)

async function loadAll() {
  loading.value = true
  try {
    const [h, m] = await Promise.all([hostsApi.list(), arpApi.modes()])
    if (h.ok) hosts.value = h.data
    if (m.ok) {
      const mm: Record<number, string> = {}
      m.data.forEach((r: any) => { mm[r.host_id] = r.mode })
      modes.value = mm
    }
  } finally {
    loading.value = false
  }
}

function showNotice(ok: boolean, text: string) {
  notice.value = { ok, text }
  setTimeout(() => (notice.value = null), 8000)
}

async function setMode(hostId: number, mode: string) {
  const res = await arpApi.setMode(hostId, mode)
  showNotice(res.ok, res.ok ? `任务已下发（#${res.job_id}），详见「任务中心」` : res.error)
  loadAll()
}

async function uninstall(hostId: number) {
  if (!confirm('确定停用该主机的 ARP 降噪？VM 网络不受影响（fail-open）。')) return
  const res = await arpApi.uninstall(hostId)
  showNotice(res.ok, res.ok ? `卸载任务已下发（#${res.job_id}）` : res.error)
  loadAll()
}

async function openDetail(hostId: number) {
  detailHost.value = hostId
  const [w, m] = await Promise.all([arpApi.whitelistList(hostId), arpApi.mapList(hostId)])
  if (w.ok) whitelist.value = w.data
  if (m.ok) maps.value = m.data
}

async function addWl() {
  if (!detailHost.value || !newWlVmid.value) return
  const res = await arpApi.whitelistAdd(detailHost.value, Number(newWlVmid.value))
  showNotice(res.ok, res.ok ? '已加入灰度白名单（同步后生效）' : res.error)
  newWlVmid.value = ''
  openDetail(detailHost.value)
}

async function delWl(id: number) {
  await arpApi.whitelistDel(id)
  if (detailHost.value) openDetail(detailHost.value)
}

async function addMap() {
  if (!detailHost.value || !newMap.value.vmid || !newMap.value.ip) return
  const res = await arpApi.mapAdd({ host_id: detailHost.value, vmid: Number(newMap.value.vmid), nic: Number(newMap.value.nic) || 0, ip: newMap.value.ip })
  showNotice(res.ok, res.ok ? '映射已添加（同步后生效）' : res.error)
  newMap.value = { vmid: '', nic: 0, ip: '' }
  openDetail(detailHost.value)
}

async function importMaps() {
  if (!detailHost.value || !importText.value.trim()) return
  const res = await arpApi.mapImport(detailHost.value, importText.value)
  showNotice(res.ok, `导入完成：新增 ${res.added}，跳过 ${res.skipped}`)
  importText.value = ''
  openDetail(detailHost.value)
}

async function delMap(id: number) {
  await arpApi.mapDel(id)
  if (detailHost.value) openDetail(detailHost.value)
}

async function syncHost(hostId: number) {
  const res = await arpApi.sync(hostId)
  showNotice(res.ok, res.ok ? `同步任务已下发（#${res.job_id}）` : res.error)
}

function modeLabel(m: string | undefined) {
  if (m === 'passive') return '被动学习'
  if (m === 'static') return '静态映射'
  return '未安装'
}

async function collectStats() {
  if (!statsHost.value) { showNotice(false, '请选择主机'); return }
  statsLoading.value = true
  try {
    const res = await arpStatsApi.collect(statsHost.value)
    if (!res.ok) { showNotice(false, res.error); return }
    const jobId = res.job_id
    for (let i = 0; i < 40; i++) {
      await new Promise(r => setTimeout(r, 1500))
      const j = await jobsApi.get(jobId)
      if (j.ok && ['succeeded', 'failed', 'rolled_back', 'rollback_failed', 'abandoned'].includes(j.data.job.status)) break
    }
    showNotice(true, '采集完成')
    loadStats()
  } finally {
    statsLoading.value = false
  }
}

async function loadStats() {
  if (!statsHost.value) { statsRows.value = []; return }
  const res = await arpStatsApi.list(statsHost.value)
  if (res.ok) statsRows.value = res.data
}
</script>

<template>
  <div>
    <div class="page-header">
      <h1 class="page-title">ARP 降噪</h1>
      <p class="page-subtitle">过滤上游网关的 ARP 广播风暴（fail-open 设计：拿不到 IP 的 VM 不装规则，绝不影响通信）</p>
    </div>

    <div v-if="notice" style="margin-bottom: 16px; padding: 12px 16px; border-radius: 12px;"
      :style="{ background: notice.ok ? 'rgba(52,199,89,0.08)' : 'rgba(255,59,48,0.08)', border: '1px solid ' + (notice.ok ? 'rgba(52,199,89,0.2)' : 'rgba(255,59,48,0.2)') }">
      <span style="font-size: 14px;">{{ notice.text }}</span>
    </div>

    <div style="display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;">
      <button v-for="t in ['mode', 'stats']" :key="t"
        class="btn" :class="tab === t ? 'btn-primary' : 'btn-secondary'" @click="setTab(t)">
        {{ { mode: '运行模式与白名单', stats: '效果统计' }[t] }}
      </button>
    </div>

    <div class="card" v-if="tab === 'mode'" id="mode">
      <div v-if="loading" style="text-align: center; padding: 40px;"><div class="spinner" style="margin: 0 auto;"></div></div>
      <div v-else class="table-container">
        <table>
          <thead><tr><th>主机</th><th>运行模式</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="h in hosts" :key="h.id">
              <td style="font-weight: 600;">{{ h.name }}</td>
              <td><span :class="['badge', modes[h.id] ? 'badge-online' : 'badge-unknown']">{{ modeLabel(modes[h.id]) }}</span></td>
              <td>
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                  <button v-if="modes[h.id] !== 'passive'" class="btn btn-sm btn-secondary" @click="setMode(h.id, 'passive')">被动学习</button>
                  <button v-if="modes[h.id] !== 'static'" class="btn btn-sm btn-secondary" @click="setMode(h.id, 'static')">静态映射</button>
                  <button v-if="modes[h.id]" class="btn btn-sm btn-secondary" @click="syncHost(h.id)">同步数据</button>
                  <button v-if="modes[h.id]" class="btn btn-sm btn-secondary" @click="openDetail(h.id)">白名单/映射</button>
                  <button v-if="modes[h.id]" class="btn btn-sm btn-danger" @click="uninstall(h.id)">停用</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 效果统计 -->
    <div class="card" v-if="tab === 'stats'" id="stats" style="margin-top: 16px;">
      <h3 style="margin: 0 0 12px; font-size: 16px;">效果统计（广播包丢弃计数，节点最近一次应用以来）</h3>
      <div style="display: flex; gap: 8px; margin-bottom: 12px;">
        <select class="form-input" v-model="statsHost" @change="loadStats" style="width: 200px;">
          <option :value="null">选择主机</option>
          <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.name }}</option>
        </select>
        <button class="btn btn-primary" @click="collectStats" :disabled="statsLoading">{{ statsLoading ? '采集中…' : '立即采集' }}</button>
      </div>
      <table v-if="statsRows.length">
        <thead><tr><th>采集时间</th><th>VM 链丢弃（按链）</th><th>BPDU 丢弃</th></tr></thead>
        <tbody>
          <tr v-for="r in statsRows" :key="r.id">
            <td>{{ r.collected_at }}</td>
            <td style="font-family: monospace; font-size: 12px;">
              {{ Object.entries(r.vm_drops).map(([k, v]) => `${k}:${v}`).join(' ') || '—' }}
            </td>
            <td>{{ r.bpdu_drops }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else style="color: #888; font-size: 13px;">暂无样本——选择主机后点「立即采集」</p>
    </div>

    <!-- 白名单与映射管理弹窗 -->
    <div v-if="detailHost" class="modal-overlay" @click.self="detailHost = null">
      <div class="modal" style="max-width: 640px;">
        <div class="modal-header">{{ hostMap[detailHost] }} · 白名单与映射</div>
        <div class="modal-body">
          <h4 style="margin: 0 0 8px; font-size: 14px;">灰度白名单（非空时只有列出的 VM 装规则）</h4>
          <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px;">
            <span v-for="w in whitelist" :key="w.id" class="badge badge-confirmed" style="cursor: pointer;" @click="delWl(w.id)" title="点击移除">
              {{ w.vmid }} ×
            </span>
            <span v-if="!whitelist.length" style="font-size: 13px; color: var(--text-tertiary);">空（全量过滤）</span>
          </div>
          <div style="display: flex; gap: 8px; margin-bottom: 20px;">
            <input class="form-input" style="width: 140px;" v-model="newWlVmid" placeholder="VMID" />
            <button class="btn btn-sm btn-primary" @click="addWl">添加</button>
          </div>

          <h4 style="margin: 0 0 8px; font-size: 14px;">静态映射表（VMID → IPv4，static 模式权威数据源）</h4>
          <table v-if="maps.length" style="margin-bottom: 8px;">
            <thead><tr><th>VMID</th><th>网卡</th><th>IP</th><th></th></tr></thead>
            <tbody>
              <tr v-for="m in maps" :key="m.id">
                <td>{{ m.vmid }}</td>
                <td>net{{ m.nic }}</td>
                <td><code style="font-size: 12px;">{{ m.ip }}</code></td>
                <td><button class="btn btn-sm btn-danger" @click="delMap(m.id)">删</button></td>
              </tr>
            </tbody>
          </table>
          <div style="display: flex; gap: 8px; margin-bottom: 8px;">
            <input class="form-input" style="width: 100px;" v-model="newMap.vmid" placeholder="VMID" />
            <input class="form-input" style="width: 70px;" v-model="newMap.nic" placeholder="net序号" type="number" />
            <input class="form-input" v-model="newMap.ip" placeholder="10.0.0.1" />
            <button class="btn btn-sm btn-primary" @click="addMap">添加</button>
          </div>
          <textarea class="form-input" v-model="importText" rows="3" placeholder="批量导入，每行: vmid,ip 或 vmid,nic,ip"></textarea>
          <button class="btn btn-sm btn-secondary" style="margin-top: 6px;" @click="importMaps">批量导入</button>
          <p style="font-size: 12px; color: var(--text-tertiary); margin-top: 12px;">改完后点「同步数据」下发到节点。</p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="detailHost = null">关闭</button>
          <button class="btn btn-primary" @click="syncHost(detailHost!)">同步数据</button>
        </div>
      </div>
    </div>
  </div>
</template>
