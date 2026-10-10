<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { resultsApi, scansApi } from '../api'
import { timeAgo } from '../time'

const stats = ref({ total_hosts: 0, online_hosts: 0, total_scans: 0, active_threats: 0, total_vms_scanned: 0 })
const recentScans = ref<any[]>([])
const recentResults = ref<any[]>([])
const loading = ref(true)

onMounted(async () => {
  try {
    const [s, scans, results] = await Promise.all([
      resultsApi.stats(),
      scansApi.list(),
      resultsApi.list(),
    ])
    if (s.ok) stats.value = s.data
    if (scans.ok) recentScans.value = scans.data.slice(0, 5)
    if (results.ok) recentResults.value = results.data.filter((r: any) => r.status !== 'clean').slice(0, 10)
  } finally {
    loading.value = false
  }
})

function statusBadge(status: string) {
  const map: Record<string, string> = {
    detected: 'badge-detected', confirmed: 'badge-confirmed',
    cleaned: 'badge-cleaned', clean: 'badge-clean',
  }
  return map[status] || 'badge-unknown'
}

function statusLabel(status: string) {
  const map: Record<string, string> = {
    detected: '新发现', confirmed: '持续存在', cleaned: '已清除', clean: '正常',
  }
  return map[status] || status
}

// timeAgo 从 ../time 导入
</script>

<template>
  <div>
    <div class="page-header">
      <h1 class="page-title">总览</h1>
      <p class="page-subtitle">PVE 切鸡检测平台</p>
    </div>

    <div class="card-grid" style="margin-bottom: 24px;">
      <div class="stat-card">
        <div class="stat-value">{{ stats.total_hosts }}</div>
        <div class="stat-label">PVE 主机</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: var(--green)">{{ stats.online_hosts }}</div>
        <div class="stat-label">在线主机</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ stats.total_vms_scanned }}</div>
        <div class="stat-label">已扫描 VM</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" :style="{ color: stats.active_threats > 0 ? 'var(--red)' : 'var(--green)' }">
          {{ stats.active_threats }}
        </div>
        <div class="stat-label">活跃威胁</div>
      </div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
      <div class="card">
        <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 16px;">最近扫描</h3>
        <div v-if="recentScans.length === 0" class="empty-state" style="padding: 30px;">
          <p>暂无扫描记录</p>
        </div>
        <div v-else>
          <div v-for="scan in recentScans" :key="scan.id" style="display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid var(--border);">
            <div>
              <div style="font-weight: 500;">扫描 #{{ scan.id }}</div>
              <div style="font-size: 13px; color: var(--text-secondary);">{{ timeAgo(scan.created_at) }}</div>
            </div>
            <div style="text-align: right;">
              <span :class="['badge', scan.found_count > 0 ? 'badge-detected' : 'badge-clean']">
                {{ scan.found_count > 0 ? scan.found_count + ' 台命中' : '全部正常' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 16px;">威胁列表</h3>
        <div v-if="recentResults.length === 0" class="empty-state" style="padding: 30px;">
          <p>暂未发现威胁</p>
        </div>
        <div v-else>
          <div v-for="r in recentResults" :key="r.id" style="display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid var(--border);">
            <div>
              <div style="font-weight: 500;">VM {{ r.vmid }}</div>
              <div style="font-size: 13px; color: var(--text-secondary);">主机 #{{ r.host_id }}</div>
            </div>
            <span :class="['badge', statusBadge(r.status)]">{{ statusLabel(r.status) }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
