<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { dashboardApi } from '../api'
import { timeAgo } from '../time'

const d = ref<any>({
  total_hosts: 0, online_hosts: 0, total_vms: 0, active_threats: 0,
  alerts_24h: 0, running_jobs: 0, failed_jobs_24h: 0,
  qos: { fresh: 0, degraded: 0, stale: 0 },
  todos: { hosts: [], jobs: [], alerts: [] },
})
const loading = ref(true)

onMounted(async () => {
  try {
    const res = await dashboardApi.overview()
    if (res.ok) d.value = res.data
  } finally {
    loading.value = false
  }
})

const todoCount = () =>
  d.value.todos.hosts.length + d.value.todos.jobs.length +
  (d.value.active_threats > 0 ? 1 : 0) + (d.value.qos.stale > 0 ? 1 : 0)
</script>

<template>
  <div>
    <div class="page-header">
      <h1 class="page-title">总览</h1>
      <p class="page-subtitle">PVE 母机一体化管控：检测 · 管控 · 优化 · QoS · 巡检</p>
    </div>

    <div v-if="loading" style="text-align: center; padding: 60px;"><div class="spinner" style="margin: 0 auto;"></div></div>

    <template v-else>
      <!-- 集群概览 -->
      <div class="card-grid" style="margin-bottom: 16px;">
        <div class="stat-card">
          <div class="stat-value">{{ d.online_hosts }}<span style="font-size: 16px; color: var(--text-tertiary);">/{{ d.total_hosts }}</span></div>
          <div class="stat-label">在线主机 / 总数</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{{ d.total_vms }}</div>
          <div class="stat-label">纳管 VM</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" :style="{ color: d.active_threats > 0 ? 'var(--red)' : 'var(--green)' }">{{ d.active_threats }}</div>
          <div class="stat-label">待处置检测结果</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" :style="{ color: d.alerts_24h > 0 ? 'var(--orange, #d97706)' : 'var(--green)' }">{{ d.alerts_24h }}</div>
          <div class="stat-label">24h 告警</div>
        </div>
      </div>

      <div class="card-grid" style="margin-bottom: 24px;">
        <div class="stat-card">
          <div class="stat-value">{{ d.running_jobs }}</div>
          <div class="stat-label">进行中任务</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" :style="{ color: d.failed_jobs_24h > 0 ? 'var(--red)' : 'var(--green)' }">{{ d.failed_jobs_24h }}</div>
          <div class="stat-label">24h 失败任务</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">
            <span style="color: var(--green)">{{ d.qos.fresh }}</span><span style="color: var(--text-tertiary);"> / </span>
            <span style="color: var(--orange, #d97706)">{{ d.qos.degraded }}</span><span style="color: var(--text-tertiary);"> / </span>
            <span style="color: var(--red)">{{ d.qos.stale }}</span>
          </div>
          <div class="stat-label">QoS 节点 正常/降级/停滞</div>
        </div>
      </div>

      <!-- 待办事项 -->
      <div class="card">
        <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 16px;">
          待办事项
          <span v-if="todoCount() > 0" class="badge badge-detected" style="margin-left: 8px;">{{ todoCount() }}</span>
        </h3>

        <div v-if="todoCount() === 0" class="empty-state" style="padding: 30px;">
          <p>一切正常，没有待办 🎉</p>
        </div>

        <div v-else>
          <div v-if="d.active_threats > 0" class="todo-row">
            <span class="badge badge-detected">检测</span>
            <span>有 <b>{{ d.active_threats }}</b> 台 VM 的检测结果待处置</span>
            <router-link to="/results" class="todo-link">去处理 →</router-link>
          </div>

          <div v-for="h in d.todos.hosts" :key="'h' + h.id" class="todo-row">
            <span class="badge badge-confirmed">主机</span>
            <span><b>{{ h.name }}</b> {{ h.status !== 'online' ? '离线或不可达' : '指纹未确认' }}</span>
            <router-link to="/hosts" class="todo-link">去处理 →</router-link>
          </div>

          <div v-for="j in d.todos.jobs" :key="'j' + j.id" class="todo-row">
            <span class="badge badge-confirmed">任务</span>
            <span>任务 #{{ j.id }}（{{ j.kind }}）{{ j.error ? '失败：' + j.error : '失败' }}</span>
            <router-link to="/jobs" class="todo-link">去处理 →</router-link>
          </div>

          <div v-if="d.qos.stale > 0" class="todo-row">
            <span class="badge badge-detected">QoS</span>
            <span><b>{{ d.qos.stale }}</b> 个 QoS 节点超时未拉取快照（stale）</span>
            <router-link to="/qos?tab=nodes" class="todo-link">去处理 →</router-link>
          </div>

          <div v-for="a in d.todos.alerts" :key="'a' + a.id" class="todo-row">
            <span class="badge" :class="a.level === 'critical' ? 'badge-detected' : 'badge-confirmed'">告警</span>
            <span>{{ a.title }} <span style="color: var(--text-tertiary); font-size: 12px;">{{ timeAgo(a.created_at) }}</span></span>
            <router-link to="/alerts#history" class="todo-link">查看 →</router-link>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.todo-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px solid var(--border);
}
.todo-row:last-child { border-bottom: none; }
.todo-row span:nth-child(2) { flex: 1; font-size: 14px; }
.todo-link { font-size: 13px; color: var(--accent); text-decoration: none; white-space: nowrap; }
.todo-link:hover { text-decoration: underline; }
</style>
