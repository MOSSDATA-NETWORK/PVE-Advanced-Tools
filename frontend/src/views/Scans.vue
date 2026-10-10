<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { scansApi, hostsApi } from '../api'
import { formatTime } from '../time'

const scans = ref<any[]>([])
const hosts = ref<any[]>([])
const loading = ref(true)
const total = ref(0)
const pageSize = ref(20)
const currentPage = ref(1)
let refreshTimer: ReturnType<typeof setInterval> | null = null

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))
const hostMap = computed(() => {
  const map: Record<number, string> = {}
  hosts.value.forEach((h: any) => { map[h.id] = h.name })
  return map
})

const pageOptions = [10, 20, 50, 100]

onMounted(async () => {
  await Promise.all([loadScans(), loadHosts()])
  startAutoRefresh()
})

async function loadHosts() {
  try {
    const res = await hostsApi.list()
    if (res.ok) hosts.value = res.data
  } catch {}
}

onUnmounted(() => {
  stopAutoRefresh()
})

async function loadScans() {
  loading.value = scans.value.length === 0
  try {
    const offset = (currentPage.value - 1) * pageSize.value
    const res = await scansApi.list(pageSize.value, offset)
    if (res.ok) {
      scans.value = res.data
      total.value = res.total || 0
    }
  } finally {
    loading.value = false
  }
}

function changePage(page: number) {
  if (page < 1 || page > totalPages.value) return
  currentPage.value = page
  loadScans()
}

function changePageSize(size: number) {
  pageSize.value = size
  currentPage.value = 1
  loadScans()
}

function hasRunningScans() {
  return scans.value.some((s: any) => s.status === 'running' || s.status === 'pending')
}

function startAutoRefresh() {
  if (refreshTimer) return
  refreshTimer = setInterval(async () => {
    await loadScans()
    if (!hasRunningScans()) stopAutoRefresh()
  }, 3000)
}

function stopAutoRefresh() {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null }
}

function statusLabel(s: string) {
  const m: Record<string, string> = { pending: '等待中', running: '运行中', completed: '已完成', failed: '失败', stopped: '已停止' }
  return m[s] || s
}

function statusBadge(s: string) {
  const m: Record<string, string> = { running: 'badge-confirmed', completed: 'badge-clean', failed: 'badge-detected', stopped: 'badge-unknown' }
  return m[s] || 'badge-unknown'
}

async function stopScan(scanId: number) {
  try {
    await scansApi.stop(scanId)
    await loadScans()
  } catch {}
}

// formatTime 从 ../time 导入

function duration(scan: any) {
  if (!scan.started_at) return '-'
  const end = scan.completed_at ? new Date(scan.completed_at).getTime() : Date.now()
  const diff = Math.floor((end - new Date(scan.started_at).getTime()) / 1000)
  if (diff < 60) return `${diff}秒`
  return `${Math.floor(diff/60)}分${diff%60}秒`
}

function progressPercent(scan: any) {
  if (scan.status !== 'running' || !scan.total_vms) return 0
  const processed = (scan.ga_count || 0) + (scan.disk_count || 0)
  return Math.min(100, Math.round((processed / scan.total_vms) * 100))
}

// 生成页码数组（带省略号）
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
    <div class="page-header">
      <div>
        <h1 class="page-title">扫描记录</h1>
        <p class="page-subtitle">查看历史扫描任务</p>
      </div>
      <button class="btn btn-secondary" @click="loadScans()">刷新</button>
    </div>

    <div class="card">
      <div v-if="loading" style="text-align: center; padding: 40px;">
        <div class="spinner" style="margin: 0 auto;"></div>
      </div>
      <div v-else-if="scans.length === 0" class="empty-state">
        <p>暂无扫描记录</p>
      </div>
      <div v-else>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>主机</th>
                <th>状态</th>
                <th>VM 总数</th>
                <th>GA</th>
                <th>磁盘</th>
                <th>命中</th>
                <th>耗时</th>
                <th>时间</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="s in scans" :key="s.id">
                <td style="font-weight: 600;">#{{ s.id }}</td>
                <td>{{ s.host_id ? (hostMap[s.host_id] || `主机 #${s.host_id}`) : '全部' }}</td>
                <td>
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span :class="['badge', statusBadge(s.status)]">{{ statusLabel(s.status) }}</span>
                    <template v-if="s.status === 'running'">
                      <div v-if="s.total_vms > 0" style="flex: 1; min-width: 60px;">
                        <div style="background: var(--border); border-radius: 4px; height: 6px; overflow: hidden;">
                          <div :style="{ width: progressPercent(s) + '%', height: '100%', background: 'var(--accent)', borderRadius: '4px', transition: 'width 0.3s' }"></div>
                        </div>
                        <div style="font-size: 11px; color: var(--text-tertiary); margin-top: 2px;">
                          {{ (s.ga_count || 0) + (s.disk_count || 0) }}/{{ s.total_vms }}
                        </div>
                      </div>
                      <div v-else class="spinner" style="width: 14px; height: 14px; border-width: 2px;"></div>
                      <button class="btn btn-sm btn-danger" @click="stopScan(s.id)" title="停止扫描">停止</button>
                    </template>
                  </div>
                </td>
                <td>{{ s.total_vms || '-' }}</td>
                <td>{{ s.ga_count || '-' }}</td>
                <td>{{ s.disk_count || '-' }}</td>
                <td>
                  <span :style="{ color: s.found_count > 0 ? 'var(--red)' : 'var(--green)', fontWeight: 600 }">
                    {{ s.found_count }}
                  </span>
                </td>
                <td>{{ duration(s) }}</td>
                <td style="font-size: 13px; color: var(--text-secondary);">{{ formatTime(s.created_at) }}</td>
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
  </div>
</template>

<style scoped>
.pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0 4px;
  flex-wrap: wrap;
  gap: 12px;
}

.pagination-info {
  font-size: 13px;
  color: var(--text-secondary);
}

.pagination-controls {
  display: flex;
  align-items: center;
  gap: 12px;
}

.page-size-select {
  padding: 6px 10px;
  border: 1px solid var(--border);
  border-radius: 8px;
  font-size: 13px;
  background: var(--bg-secondary);
  color: var(--text);
  cursor: pointer;
  font-family: var(--font);
}

.page-buttons {
  display: flex;
  align-items: center;
  gap: 4px;
}

.page-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 32px;
  height: 32px;
  padding: 0 6px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-secondary);
  color: var(--text);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  font-family: var(--font);
}

.page-btn:hover:not(:disabled):not(.active) {
  background: rgba(0,0,0,0.04);
}

.page-btn.active {
  background: var(--accent);
  color: white;
  border-color: var(--accent);
}

.page-btn:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.page-ellipsis {
  padding: 0 4px;
  color: var(--text-tertiary);
  font-size: 13px;
}

@media (max-width: 768px) {
  .pagination {
    flex-direction: column;
    align-items: stretch;
  }
  .pagination-controls {
    justify-content: space-between;
  }
}
</style>
