<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import { computed, ref, onMounted, watch } from 'vue'
import { versionApi } from '../api'

const route = useRoute()
const router = useRouter()
const currentRoute = computed(() => route.name)
const appVersion = ref('')
const updateAvailable = ref(false)
const latestVersion = ref('')
const sidebarOpen = ref(false)

const navItems = [
  { name: 'dashboard', label: '总览', path: '/' },
  { name: 'hosts', label: '主机管理', path: '/hosts' },
  { name: 'scans', label: '扫描记录', path: '/scans' },
  { name: 'results', label: '检测结果', path: '/results' },
  { name: 'jobs', label: '任务中心', path: '/jobs' },
  { name: 'netguard', label: '出网管控', path: '/netguard' },
  { name: 'arp', label: 'ARP 降噪', path: '/arp' },
  { name: 'optimize', label: '母机优化', path: '/optimize' },
  { name: 'qos', label: '带宽 QoS', path: '/qos' },
  { name: 'alerts', label: '告警与巡检', path: '/alerts' },
  { name: 'audit', label: '审计日志', path: '/audit' },
  { name: 'settings', label: '设置', path: '/settings' },
]

const pageTitle = computed(() => {
  const item = navItems.find(n => n.name === currentRoute.value)
  return item?.label || 'PVE Advanced Tools'
})

async function checkVersion() {
  try {
    const res = await versionApi.current()
    if (res.ok) appVersion.value = res.version
  } catch {}
  try {
    const res = await versionApi.check()
    if (res.ok && res.data?.update_available) {
      updateAvailable.value = true
      latestVersion.value = res.data.latest
    } else {
      updateAvailable.value = false
    }
  } catch {}
}

onMounted(checkVersion)

// 路由切换时刷新版本 + 关闭侧边栏
watch(() => route.path, () => {
  sidebarOpen.value = false
  checkVersion()
})

function navigate(path: string) {
  router.push(path)
  sidebarOpen.value = false
}

function toggleSidebar() {
  sidebarOpen.value = !sidebarOpen.value
}

function goToSettings() {
  router.push('/settings')
  sidebarOpen.value = false
}
</script>

<template>
  <!-- Mobile Header -->
  <header class="mobile-header">
    <button class="hamburger" @click="toggleSidebar">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24">
        <line x1="3" y1="6" x2="21" y2="6"/>
        <line x1="3" y1="12" x2="21" y2="12"/>
        <line x1="3" y1="18" x2="21" y2="18"/>
      </svg>
    </button>
    <span class="mobile-title">{{ pageTitle }}</span>
  </header>

  <!-- Sidebar Overlay -->
  <div class="sidebar-overlay" :class="{ open: sidebarOpen }" @click="sidebarOpen = false"></div>

  <div class="app-layout">
    <aside class="sidebar" :class="{ open: sidebarOpen }">
      <div class="sidebar-logo">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        PVE Advanced Tools
      </div>
      <nav class="sidebar-nav">
        <div
          v-for="item in navItems"
          :key="item.name"
          class="nav-item"
          :class="{ active: currentRoute === item.name }"
          @click="navigate(item.path)"
        >
          <svg v-if="item.name === 'dashboard'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
          <svg v-else-if="item.name === 'hosts'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
          <svg v-else-if="item.name === 'scans'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
          <svg v-else-if="item.name === 'results'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <svg v-else-if="item.name === 'jobs'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
          <svg v-else-if="item.name === 'netguard'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="4" y1="4" x2="20" y2="20"/></svg>
          <svg v-else-if="item.name === 'arp'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          <svg v-else-if="item.name === 'optimize'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
          <svg v-else-if="item.name === 'qos'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 14l4-4"/><path d="M3.34 19a10 10 0 1117.32 0"/></svg>
          <svg v-else-if="item.name === 'alerts'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
          <svg v-else-if="item.name === 'audit'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
          <svg v-else-if="item.name === 'settings'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
          {{ item.label }}
        </div>
      </nav>
      <div class="sidebar-footer">
        <div v-if="updateAvailable" class="update-banner" @click="goToSettings">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          <span>新版本 v{{ latestVersion }} 可用</span>
        </div>
        <div class="version-text">v{{ appVersion || '...' }}</div>
      </div>
    </aside>
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<style scoped>
.sidebar-footer {
  padding: 12px;
}

.update-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  background: linear-gradient(135deg, rgba(0,122,255,0.08), rgba(88,86,214,0.08));
  border: 1px solid rgba(0,122,255,0.12);
  border-radius: 10px;
  font-size: 12px;
  font-weight: 500;
  color: var(--accent);
  cursor: pointer;
  margin-bottom: 8px;
  transition: all 0.2s;
}

.update-banner:hover {
  background: rgba(0,122,255,0.15);
}

.version-text {
  font-size: 12px;
  color: var(--text-tertiary);
}
</style>
