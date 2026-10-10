<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { jobsApi, hostsApi } from '../api'
import { formatTime } from '../time'

const jobs = ref<any[]>([])
const hosts = ref<any[]>([])
const loading = ref(true)
const filterHost = ref<number | null>(null)
const filterStatus = ref('')
const detail = ref<{ job: any; steps: any[] } | null>(null)
const actionMsg = ref<{ ok: boolean; text: string } | null>(null)

const hostMap = computed(() => {
  const map: Record<number, string> = {}
  hosts.value.forEach((h: any) => { map[h.id] = h.name })
  return map
})

onMounted(async () => {
  try {
    const h = await hostsApi.list()
    if (h.ok) hosts.value = h.data
  } catch {}
  await loadJobs()
})

async function loadJobs() {
  loading.value = true
  try {
    const params: any = { limit: 100 }
    if (filterHost.value) params.host_id = filterHost.value
    if (filterStatus.value) params.status = filterStatus.value
    const res = await jobsApi.list(params)
    if (res.ok) jobs.value = res.data
  } finally {
    loading.value = false
  }
}

function onFilterChange() { loadJobs() }

async function openDetail(id: number) {
  const res = await jobsApi.get(id)
  if (res.ok) detail.value = res.data
}

async function retryJob(id: number) {
  actionMsg.value = null
  const res = await jobsApi.retry(id)
  actionMsg.value = res.ok
    ? { ok: true, text: `任务 #${id} 已重新入队（从检查点续跑）` }
    : { ok: false, text: res.error || '重跑失败' }
  await loadJobs()
  if (detail.value?.job?.id === id) openDetail(id)
}

function statusBadge(s: string) {
  const m: Record<string, string> = {
    queued: 'badge-confirmed', running: 'badge-confirmed', succeeded: 'badge-clean',
    failed: 'badge-detected', rolled_back: 'badge-cleaned', abandoned: 'badge-unknown',
  }
  return m[s] || 'badge-unknown'
}

function statusLabel(s: string) {
  const m: Record<string, string> = {
    queued: '排队中', running: '执行中', succeeded: '成功',
    failed: '失败', rolled_back: '已回滚', abandoned: '已放弃',
  }
  return m[s] || s
}

function stepStatusLabel(s: string) {
  const m: Record<string, string> = {
    pending: '等待', running: '执行中', succeeded: '成功', failed: '失败',
    skipped: '跳过', rolled_back: '已回滚', rollback_failed: '回滚失败',
  }
  return m[s] || s
}

function policyLabel(p: string) {
  return p === 'fail_open' ? 'fail-open（不断网）' : 'fail-closed（失败回滚）'
}
</script>

<template>
  <div>
    <div class="page-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
      <div>
        <h1 class="page-title">任务中心</h1>
        <p class="page-subtitle">主机任务下发与执行回采（同主机串行，支持检查点续跑与回滚）</p>
      </div>
      <div style="display: flex; gap: 12px;">
        <select class="form-input" style="width: 160px;" v-model="filterHost" @change="onFilterChange">
          <option :value="null">全部主机</option>
          <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.name }}</option>
        </select>
        <select class="form-input" style="width: 140px;" v-model="filterStatus" @change="onFilterChange">
          <option value="">全部状态</option>
          <option value="queued">排队中</option>
          <option value="running">执行中</option>
          <option value="succeeded">成功</option>
          <option value="failed">失败</option>
          <option value="rolled_back">已回滚</option>
          <option value="abandoned">已放弃</option>
        </select>
      </div>
    </div>

    <div v-if="actionMsg" style="margin-bottom: 16px; padding: 12px 16px; border-radius: 12px;"
      :style="{ background: actionMsg.ok ? 'rgba(52,199,89,0.08)' : 'rgba(255,59,48,0.08)', border: '1px solid ' + (actionMsg.ok ? 'rgba(52,199,89,0.2)' : 'rgba(255,59,48,0.2)') }">
      <span style="font-size: 14px;">{{ actionMsg.text }}</span>
    </div>

    <div class="card">
      <div v-if="loading" style="text-align: center; padding: 40px;">
        <div class="spinner" style="margin: 0 auto;"></div>
      </div>
      <div v-else-if="jobs.length === 0" class="empty-state">
        <p>暂无任务</p>
      </div>
      <div v-else class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>主机</th>
              <th>类型</th>
              <th>序号</th>
              <th>状态</th>
              <th>失败策略</th>
              <th>创建者</th>
              <th>创建时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="j in jobs" :key="j.id">
              <td style="font-weight: 600;">#{{ j.id }}</td>
              <td>{{ hostMap[j.host_id] || `#${j.host_id}` }}</td>
              <td><code style="font-size: 12px;">{{ j.kind }}</code></td>
              <td>{{ j.seq }}</td>
              <td><span :class="['badge', statusBadge(j.status)]">{{ statusLabel(j.status) }}</span></td>
              <td style="font-size: 12px;">{{ policyLabel(j.failure_policy) }}</td>
              <td style="font-size: 13px;">{{ j.created_by || '-' }}</td>
              <td style="font-size: 13px; color: var(--text-secondary);">{{ formatTime(j.created_at) }}</td>
              <td style="white-space: nowrap;">
                <button class="btn btn-sm btn-secondary" @click="openDetail(j.id)">详情</button>
                <button v-if="['failed','rolled_back','abandoned'].includes(j.status)"
                  class="btn btn-sm btn-primary" style="margin-left: 6px;" @click="retryJob(j.id)">重跑</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 任务详情弹窗 -->
    <div v-if="detail" class="modal-overlay" @click.self="detail = null">
      <div class="modal" style="max-width: 640px;">
        <div class="modal-header">任务 #{{ detail.job.id }} · {{ detail.job.kind }}</div>
        <div class="modal-body">
          <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 14px; font-size: 13px; color: var(--text-secondary);">
            <span>状态：<b style="color: var(--text);">{{ statusLabel(detail.job.status) }}</b></span>
            <span>策略：{{ policyLabel(detail.job.failure_policy) }}</span>
            <span>检查点：步骤 {{ detail.job.checkpoint_step }}</span>
          </div>
          <div v-if="detail.job.error" style="padding: 10px 14px; margin-bottom: 12px; border-radius: 10px; background: rgba(255,59,48,0.06); border: 1px solid rgba(255,59,48,0.15); font-size: 13px;">
            {{ detail.job.error }}
          </div>
          <div v-for="s in detail.steps" :key="s.id"
            style="padding: 10px 14px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="font-weight: 600; font-size: 14px;">{{ s.seq }}. {{ s.name }}</div>
              <span :class="['badge', statusBadge(s.status === 'rolled_back' ? 'rolled_back' : s.status)]">{{ stepStatusLabel(s.status) }}</span>
            </div>
            <code style="font-size: 12px; color: var(--text-secondary); word-break: break-all; display: block; margin-top: 4px;">{{ s.command }}</code>
            <pre v-if="s.output" style="font-size: 12px; background: var(--bg-secondary); padding: 8px; border-radius: 8px; margin-top: 6px; max-height: 160px; overflow: auto; white-space: pre-wrap; word-break: break-all;">{{ s.output }}</pre>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="detail = null">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>
