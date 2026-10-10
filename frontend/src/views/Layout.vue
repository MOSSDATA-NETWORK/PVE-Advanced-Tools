<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import { computed, ref, onMounted, watch } from 'vue'
import { versionApi } from '../api'

const route = useRoute()
const router = useRouter()
const appVersion = ref('')
const updateAvailable = ref(false)
const latestVersion = ref('')
const sidebarOpen = ref(false)

interface SubItem { label: string; path: string }
interface NavGroup { name: string; label: string; icon: string; path?: string; children?: SubItem[] }

// 菜单结构对齐大纲：一级功能域 + 二级子项；二级项指向页面内分区（hash 锚点或 ?tab=）
const navGroups: NavGroup[] = [
  { name: 'dashboard', label: '总览', icon: 'dashboard', path: '/' },
  {
    name: 'hosts', label: '宿主机管理', icon: 'hosts',
    children: [
      { label: '主机列表', path: '/hosts' },
      { label: '添加主机', path: '/hosts#add' },
      { label: '任务中心', path: '/jobs' },
    ],
  },
  {
    name: 'detect', label: '切鸡检测', icon: 'scans',
    children: [
      { label: '扫描任务', path: '/scans' },
      { label: '检测结果', path: '/results' },
    ],
  },
  {
    name: 'netguard', label: '出网管控', icon: 'netguard',
    children: [
      { label: '生效范围', path: '/netguard#scope' },
      { label: '端口封堵', path: '/netguard#ports' },
      { label: '域名拦截', path: '/netguard#domains' },
      { label: 'VM 白名单', path: '/netguard#whitelist' },
    ],
  },
  {
    name: 'arp', label: 'ARP 降噪', icon: 'arp',
    children: [
      { label: '运行模式', path: '/arp#mode' },
      { label: '白名单管理', path: '/arp' },
    ],
  },
  {
    name: 'qos', label: '带宽 QoS', icon: 'qos',
    children: [
      { label: '节点状态', path: '/qos?tab=nodes' },
      { label: '带宽策略', path: '/qos?tab=policies' },
      { label: '阶梯档位', path: '/qos?tab=templates' },
      { label: '限速事件流', path: '/qos?tab=events' },
      { label: '快照 API 接入', path: '/qos?tab=access' },
    ],
  },
  {
    name: 'optimize', label: '母机优化', icon: 'optimize',
    children: [
      { label: '一键初始化', path: '/optimize#init' },
      { label: '参数优化', path: '/optimize#tune' },
      { label: '回滚中心', path: '/optimize#rollback' },
    ],
  },
  {
    name: 'alerts', label: '告警与巡检', icon: 'alerts',
    children: [
      { label: '巡检计划', path: '/alerts#inspect' },
      { label: '告警规则', path: '/alerts#rules' },
      { label: '告警历史', path: '/alerts#history' },
    ],
  },
  {
    name: 'settings', label: '系统设置', icon: 'settings',
    children: [
      { label: '账户与安全', path: '/settings#account' },
      { label: '通知渠道', path: '/settings#notify' },
      { label: '审计日志', path: '/audit' },
      { label: '关于与更新', path: '/settings#about' },
    ],
  },
]

// 当前路由归属的一级组
const activeGroup = computed(() => {
  const p = route.path
  if (p === '/') return 'dashboard'
  if (p.startsWith('/hosts') || p.startsWith('/jobs')) return 'hosts'
  if (p.startsWith('/scans') || p.startsWith('/results')) return 'detect'
  for (const g of navGroups) {
    if (g.children && p.startsWith('/' + g.name)) return g.name
  }
  if (p.startsWith('/audit')) return 'settings'
  return ''
})

const expanded = ref<Record<string, boolean>>({ hosts: true })
function toggleGroup(name: string) {
  expanded.value[name] = !expanded.value[name]
}
function isExpanded(name: string) {
  return expanded.value[name] ?? activeGroup.value === name
}

const pageTitle = computed(() => {
  const g = navGroups.find(g => g.name === activeGroup.value)
  return g?.label || 'PVE Advanced Tools'
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

watch(() => route.path, () => {
  sidebarOpen.value = false
  checkVersion()
})

function toggleSidebar() {
  sidebarOpen.value = !sidebarOpen.value
}

function navigate(path: string) {
  // 同页二级跳转（仅 hash/query 变化）也要滚到锚点
  router.push(path)
  sidebarOpen.value = false
}

function goToSettings() {
  router.push('/settings#about')
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
        <template v-for="group in navGroups" :key="group.name">
          <!-- 无子项的一级项（总览） -->
          <div
            v-if="!group.children"
            class="nav-item"
            :class="{ active: activeGroup === group.name }"
            @click="navigate(group.path!)"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
            {{ group.label }}
          </div>
          <!-- 有子项的一级组（可折叠） -->
          <div v-else>
            <div
              class="nav-item nav-group-header"
              :class="{ active: activeGroup === group.name }"
              @click="toggleGroup(group.name)"
            >
              <svg v-if="group.icon === 'hosts'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
              <svg v-else-if="group.icon === 'scans'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
              <svg v-else-if="group.icon === 'netguard'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="4" y1="4" x2="20" y2="20"/></svg>
              <svg v-else-if="group.icon === 'arp'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              <svg v-else-if="group.icon === 'qos'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 14l4-4"/><path d="M3.34 19a10 10 0 1117.32 0"/></svg>
              <svg v-else-if="group.icon === 'optimize'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
              <svg v-else-if="group.icon === 'alerts'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
              <svg v-else-if="group.icon === 'settings'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
              <span style="flex: 1;">{{ group.label }}</span>
              <svg class="chevron" :class="{ open: isExpanded(group.name) }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="6 9 12 15 18 9"/></svg>
            </div>
            <div v-show="isExpanded(group.name)" class="nav-children">
              <div
                v-for="sub in group.children"
                :key="sub.path"
                class="nav-subitem"
                :class="{ active: route.fullPath === sub.path || (sub.path.split(/[#?]/)[0] !== '/' && false) }"
                @click="navigate(sub.path)"
              >
                {{ sub.label }}
              </div>
            </div>
          </div>
        </template>
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

.nav-group-header .chevron {
  transition: transform 0.2s;
  flex-shrink: 0;
}
.nav-group-header .chevron.open {
  transform: rotate(180deg);
}

.nav-children {
  margin: 2px 0 6px;
}

.nav-subitem {
  padding: 7px 12px 7px 40px;
  font-size: 13px;
  color: var(--text-secondary, #666);
  cursor: pointer;
  border-radius: 8px;
  margin: 1px 8px;
  transition: all 0.15s;
}

.nav-subitem:hover {
  background: rgba(0, 122, 255, 0.08);
  color: var(--accent, #007aff);
}

.nav-subitem.active {
  color: var(--accent, #007aff);
  font-weight: 500;
}
</style>
