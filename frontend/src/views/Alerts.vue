<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { hostsApi } from '../api'
import { formatTime } from '../time'
import axios from 'axios'

const rules = ref<any[]>([])
const history = ref<any[]>([])
const hosts = ref<any[]>([])
const total = ref(0)
const pageSize = 50
const currentPage = ref(1)
const loading = ref(true)
const notice = ref<{ ok: boolean; text: string } | null>(null)
const inspectEnabled = ref(true)
const inspectInterval = ref(60)
const newRule = ref({ name: '', trigger_type: 'host_offline', threshold: 90 })

const hostMap = computed(() => {
  const m: Record<number, string> = {}
  hosts.value.forEach((h: any) => { m[h.id] = h.name })
  return m
})
const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))

const triggerLabels: Record<string, string> = {
  host_offline: '节点离线/巡检失败',
  job_failed: '任务执行失败',
  resource_high: '资源水位过高',
  inspect_failed: '管控组件失效',
}

onMounted(loadAll)

async function loadAll() {
  loading.value = true
  try {
    const [r, h, s, hs] = await Promise.all([
      axios.get('/api/alerts/rules'),
      axios.get('/api/alerts/history', { params: { limit: pageSize, offset: (currentPage.value - 1) * pageSize } }),
      axios.get('/api/inspect/settings'),
      hostsApi.list(),
    ])
    if (r.data.ok) rules.value = r.data.data
    if (h.data.ok) { history.value = h.data.data; total.value = h.data.total }
    if (s.data.ok) { inspectEnabled.value = s.data.enabled; inspectInterval.value = s.data.interval_mins }
    if (hs.ok) hosts.value = hs.data
  } finally {
    loading.value = false
  }
}

function showNotice(ok: boolean, text: string) {
  notice.value = { ok, text }
  setTimeout(() => (notice.value = null), 6000)
}

async function addRule() {
  if (!newRule.value.name.trim()) return
  const body: any = { name: newRule.value.name, trigger_type: newRule.value.trigger_type }
  if (newRule.value.trigger_type === 'resource_high') body.threshold = Number(newRule.value.threshold)
  const res = await axios.post('/api/alerts/rules', body)
  showNotice(res.data.ok, res.data.ok ? '规则已添加' : res.data.error)
  if (res.data.ok) { newRule.value.name = ''; loadAll() }
}

async function toggleRule(id: number) {
  await axios.post(`/api/alerts/rules/${id}/toggle`)
  loadAll()
}

async function delRule(id: number) {
  await axios.delete(`/api/alerts/rules/${id}`)
  loadAll()
}

async function saveInspect() {
  const res = await axios.put('/api/inspect/settings', { enabled: inspectEnabled.value, interval_mins: Number(inspectInterval.value) })
  showNotice(res.data.ok, res.data.ok ? '巡检设置已保存' : res.data.error)
}

async function inspectNow(hostId: number) {
  const res = await axios.post(`/api/inspect/${hostId}`)
  showNotice(res.data.ok, res.data.ok ? `巡检任务已下发（#${res.data.job_id}）` : res.data.error)
}

function changePage(p: number) {
  if (p < 1 || p > totalPages.value) return
  currentPage.value = p
  loadAll()
}
</script>

<template>
  <div>
    <div class="page-header">
      <h1 class="page-title">告警与巡检</h1>
      <p class="page-subtitle">告警规则（通知渠道在「设置」配置 Telegram / 企业微信）、定时巡检、告警历史</p>
    </div>

    <div v-if="notice" style="margin-bottom: 16px; padding: 12px 16px; border-radius: 12px;"
      :style="{ background: notice.ok ? 'rgba(52,199,89,0.08)' : 'rgba(255,59,48,0.08)', border: '1px solid ' + (notice.ok ? 'rgba(52,199,89,0.2)' : 'rgba(255,59,48,0.2)') }">
      <span style="font-size: 14px;">{{ notice.text }}</span>
    </div>

    <!-- 巡检设置 -->
    <div class="card" style="margin-bottom: 16px;">
      <h3 style="margin: 0 0 12px; font-size: 16px;">定时巡检（检测组件存活 + 资源水位）</h3>
      <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
        <label style="display: flex; align-items: center; gap: 6px; font-size: 14px;">
          <input type="checkbox" v-model="inspectEnabled" /> 启用定时巡检
        </label>
        <label style="font-size: 14px;">每
          <input class="form-input" style="width: 80px; display: inline-block;" type="number" v-model="inspectInterval" min="15" max="1440" />
          分钟
        </label>
        <button class="btn btn-sm btn-primary" @click="saveInspect">保存</button>
        <span style="flex: 1;"></span>
        <template v-for="h in hosts" :key="h.id">
          <button class="btn btn-sm btn-secondary" @click="inspectNow(h.id)">巡检 {{ h.name }}</button>
        </template>
      </div>
    </div>

    <!-- 告警规则 -->
    <div class="card" style="margin-bottom: 16px;">
      <h3 style="margin: 0 0 12px; font-size: 16px;">告警规则</h3>
      <div class="table-container">
        <table>
          <thead><tr><th>名称</th><th>触发条件</th><th>阈值</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="r in rules" :key="r.id">
              <td style="font-weight: 600;">{{ r.name }}</td>
              <td>{{ triggerLabels[r.trigger_type] || r.trigger_type }}</td>
              <td>{{ r.threshold ? r.threshold + '%' : '-' }}</td>
              <td><span :class="['badge', r.enabled ? 'badge-online' : 'badge-unknown']">{{ r.enabled ? '启用' : '停用' }}</span></td>
              <td>
                <button class="btn btn-sm btn-secondary" @click="toggleRule(r.id)">{{ r.enabled ? '停用' : '启用' }}</button>
                <button class="btn btn-sm btn-danger" style="margin-left: 6px;" @click="delRule(r.id)">删除</button>
              </td>
            </tr>
            <tr>
              <td><input class="form-input" v-model="newRule.name" placeholder="规则名称" /></td>
              <td>
                <select class="form-input" v-model="newRule.trigger_type">
                  <option v-for="(label, key) in triggerLabels" :key="key" :value="key">{{ label }}</option>
                </select>
              </td>
              <td><input v-if="newRule.trigger_type === 'resource_high'" class="form-input" style="width: 80px;" type="number" v-model="newRule.threshold" min="1" max="100" /><span v-else>-</span></td>
              <td colspan="2"><button class="btn btn-sm btn-primary" @click="addRule">添加</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 告警历史 -->
    <div class="card">
      <h3 style="margin: 0 0 12px; font-size: 16px;">告警历史</h3>
      <div v-if="loading" style="text-align: center; padding: 40px;"><div class="spinner" style="margin: 0 auto;"></div></div>
      <div v-else-if="!history.length" class="empty-state"><p>暂无告警</p></div>
      <div v-else>
        <div class="table-container">
          <table>
            <thead><tr><th>时间</th><th>级别</th><th>标题</th><th>主机</th><th>详情</th><th>已通知</th></tr></thead>
            <tbody>
              <tr v-for="a in history" :key="a.id">
                <td style="font-size: 13px; color: var(--text-secondary); white-space: nowrap;">{{ formatTime(a.created_at) }}</td>
                <td><span :class="['badge', a.level === 'critical' ? 'badge-detected' : 'badge-confirmed']">{{ a.level === 'critical' ? '严重' : '警告' }}</span></td>
                <td style="font-weight: 600;">{{ a.title }}</td>
                <td>{{ a.host_id ? (hostMap[a.host_id] || '#' + a.host_id) : '-' }}</td>
                <td style="font-size: 13px; color: var(--text-secondary); max-width: 320px;">{{ a.message || '-' }}</td>
                <td>{{ a.notified ? '✅' : '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 16px 0 4px;">
          <span style="font-size: 13px; color: var(--text-secondary);">共 {{ total }} 条，第 {{ currentPage }}/{{ totalPages }} 页</span>
          <div style="display: flex; gap: 8px;">
            <button class="btn btn-sm btn-secondary" :disabled="currentPage <= 1" @click="changePage(currentPage - 1)">上一页</button>
            <button class="btn btn-sm btn-secondary" :disabled="currentPage >= totalPages" @click="changePage(currentPage + 1)">下一页</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
