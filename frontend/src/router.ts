import { createRouter, createWebHistory } from 'vue-router'
import axios from 'axios'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    // 不带侧边栏的页面
    { path: '/setup', name: 'setup', component: () => import('./views/Setup.vue') },
    { path: '/login', name: 'login', component: () => import('./views/Login.vue') },

    // 带侧边栏的页面
    {
      path: '/',
      component: () => import('./views/Layout.vue'),
      children: [
        { path: '', name: 'dashboard', component: () => import('./views/Dashboard.vue') },
        { path: 'hosts', name: 'hosts', component: () => import('./views/Hosts.vue') },
        { path: 'scans', name: 'scans', component: () => import('./views/Scans.vue') },
        { path: 'results', name: 'results', component: () => import('./views/Results.vue') },
        { path: 'jobs', name: 'jobs', component: () => import('./views/Jobs.vue') },
        { path: 'netguard', name: 'netguard', component: () => import('./views/Netguard.vue') },
        { path: 'arp', name: 'arp', component: () => import('./views/Arp.vue') },
        { path: 'optimize', name: 'optimize', component: () => import('./views/Optimize.vue') },
        { path: 'qos', name: 'qos', component: () => import('./views/Qos.vue') },
        { path: 'alerts', name: 'alerts', component: () => import('./views/Alerts.vue') },
        { path: 'audit', name: 'audit', component: () => import('./views/AuditLog.vue') },
        { path: 'settings', name: 'settings', component: () => import('./views/Settings.vue') },
      ]
    },
  ]
})

router.beforeEach(async (to, _from, next) => {
  // Setup 和 Login 页面直接放行
  if (to.name === 'setup' || to.name === 'login') {
    next()
    return
  }

  try {
    const res = await axios.get('/api/auth/check')
    if (!res.data.initialized) {
      // 未初始化 → 跳 setup
      next({ name: 'setup' })
      return
    }
  } catch {
    next({ name: 'login' })
    return
  }

  // 已初始化，检查是否已登录
  try {
    await axios.get('/api/results/stats')
    next()
  } catch (e: any) {
    if (e.response?.status === 401) {
      next({ name: 'login' })
    } else {
      next()
    }
  }
})

export default router
