<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { auditApi } from '../api'
import { formatTime } from '../time'

const logs = ref<any[]>([])
const loading = ref(true)
const total = ref(0)
const pageSize = ref(50)
const currentPage = ref(1)
const filterAction = ref('')
const filterActor = ref('')
const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))

onMounted(loadLogs)

async function loadLogs() {
  loading.value = true
  try {
    const params: any = { limit: pageSize.value, offset: (currentPage.value - 1) * pageSize.value }
    if (filterAction.value) params.action = filterAction.value
    if (filterActor.value) params.actor = filterActor.value
    const res = await auditApi.list(params)
    if (res.ok) {
      logs.value = res.data
      total.value = res.total || 0
    }
  } finally {
    loading.value = false
  }
}

function onFilterChange() {
  currentPage.value = 1
  loadLogs()
}

function changePage(page: number) {
  if (page < 1 || page > totalPages.value) return
  currentPage.value = page
  loadLogs()
}
</script>

<template>
  <div>
    <div class="page-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
      <div>
        <h1 class="page-title">审计日志</h1>
        <p class="page-subtitle">谁在什么时候对哪台主机做了什么</p>
      </div>
      <div style="display: flex; gap: 12px;">
        <input class="form-input" style="width: 160px;" v-model="filterAction" placeholder="操作，如 host." @change="onFilterChange" />
        <input class="form-input" style="width: 140px;" v-model="filterActor" placeholder="操作者" @change="onFilterChange" />
      </div>
    </div>

    <div class="card">
      <div v-if="loading" style="text-align: center; padding: 40px;">
        <div class="spinner" style="margin: 0 auto;"></div>
      </div>
      <div v-else-if="logs.length === 0" class="empty-state">
        <p>暂无审计记录</p>
      </div>
      <div v-else>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>时间</th>
                <th>操作者</th>
                <th>操作</th>
                <th>对象</th>
                <th>详情</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="l in logs" :key="l.id">
                <td style="font-size: 13px; color: var(--text-secondary); white-space: nowrap;">{{ formatTime(l.created_at) }}</td>
                <td style="font-weight: 600;">{{ l.actor }}</td>
                <td><code style="font-size: 12px;">{{ l.action }}</code></td>
                <td style="font-size: 13px;">{{ l.target_type ? `${l.target_type}${l.target_id ? ' #' + l.target_id : ''}` : '-' }}</td>
                <td style="font-size: 13px; color: var(--text-secondary); max-width: 320px; word-break: break-all;">{{ l.detail || '-' }}</td>
                <td style="font-size: 12px; color: var(--text-tertiary);">{{ l.ip || '-' }}</td>
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
