<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { hostsApi, vmsApi, jobsApi, qosApi, netguardApi, arpApi, optimizeApi } from '../api'

const route = useRoute()
const hostId = Number(route.params.id)
const tab = ref<string>((route.query.tab as string) || 'overview')
const host = ref<any>(null)
const components = ref<any[]>([])
const vms = ref<any[]>([])
const jobs = ref<any[]>([])
const loading = ref(true)
const notice = ref<{ ok: boolean; text: string } | null>(null)

onMounted(loadAll)

async function loadAll() {
  loading.value = true
  try {
    const [h, c, v, j] = await Promise.all([
      hostsApi.get(hostId),
      hostsApi.components(hostId),
      vmsApi.list(hostId),
      jobsApi.list({ host_id: hostId, limit: 50 }),
    ])
    if (h.ok) host.value = h.data
    if (c.ok) components.value = c.data
    if (v.ok) vms.value = v.data
    if (j.ok) jobs.value = j.data
  } finally {
    loading.value = false
  }
}

function flash(ok: boolean, text: string) {
  notice.value = { ok, text }
  setTimeout(() => { notice.value = null }, 5000)
}

function compInstalled(name: string) {
  return components.value.some(c => c.component === name)
}

async function run(fn: () => Promise<any>, label: string) {
  const res = await fn()
  flash(res.ok, res.ok ? `${label}任务已创建` : res.error)
}

const compActions = computed(() => ([
  {
    name: 'netguard', label: '出网管控（netguard）',
    install: () => netguardApi.deploy(),
    uninstall: null,
    note: '安装/更新请到「出网管控」页按生效范围下发',
  },
  {
    name: 'arpfilter', label: 'ARP 降噪（arpfilter）',
    install: null, uninstall: () => arpApi.uninstall(hostId),
    note: '模式切换到「ARP 降噪」页操作；此处可卸载',
  },
  {
    name: 'nosub', label: '一键初始化（nosub）',
    install: () => optimizeApi.init(hostId), uninstall: null,
    note: '换 no-subscription 源 + 去订阅弹窗',
  },
  {
    name: 'optimize', label: '参数优化（pve-optimize）',
    install: () => optimizeApi.tune(hostId), uninstall: null,
    note: 'sysctl/THP/KSM/IO/ZFS ARC；回滚见「回滚」页签',
  },
  {
    name: 'vmqos', label: '带宽 QoS（vmqos）',
    install: () => qosApi.install(hostId), uninstall: () => qosApi.uninstall(hostId),
    note: '需先在「带宽 QoS → 快照 API 接入」签发 token',
  },
]))

const jobStatusLabel: Record<string, string> = {
  queued: '排队中', running: '运行中', succeeded: '成功', failed: '失败',
  rolled_back: '已回滚', rollback_failed: '回滚失败', abandoned: '已放弃',
}
</script>

<template>
  <div>
    <div class="page-header">
      <h1 class="page-title">{{ host?.name || '主机详情' }}</h1>
      <p class="page-subtitle" v-if="host">
        {{ host.host }}:{{ host.port }} ·
        指纹{{ host.host_key_status === 'confirmed' ? '已确认' : '未确认' }} ·
        {{ host.pve_version ? 'PVE ' + host.pve_version : '版本未知' }}
      </p>
    </div>

    <div v-if="notice" :class="notice.ok ? 'notice-ok' : 'notice-err'" style="margin-bottom: 12px;">{{ notice.text }}</div>

    <div style="display: flex; gap: 8px; margin-bottom: 16px;">
      <button v-for="t in ['overview', 'components', 'vms', 'jobs', 'rollback']" :key="t"
        class="btn" :class="tab === t ? 'btn-primary' : 'btn-secondary'" @click="tab = t">
        {{ { overview: '概览', components: '组件管理', vms: 'VM 列表', jobs: '任务历史', rollback: '回滚操作' }[t] }}
      </button>
    </div>

    <div v-if="loading" style="text-align: center; padding: 40px;"><div class="spinner" style="margin: 0 auto;"></div></div>

    <!-- 概览 -->
    <div v-else-if="tab === 'overview' && host" class="card">
      <table>
        <tbody>
          <tr><td style="width: 140px; color: var(--text-secondary);">状态</td><td>{{ host.status }}</td></tr>
          <tr><td style="color: var(--text-secondary);">地址</td><td>{{ host.host }}:{{ host.port }}（{{ host.username }}@{{ host.auth_type }}）</td></tr>
          <tr><td style="color: var(--text-secondary);">主机密钥指纹</td><td style="font-family: monospace; font-size: 12px;">{{ host.host_key_fingerprint || '未获取' }}</td></tr>
          <tr><td style="color: var(--text-secondary);">PVE 版本</td><td>{{ host.pve_version || '未知（点「探测」获取）' }}</td></tr>
          <tr><td style="color: var(--text-secondary);">检测脚本</td><td>{{ host.agent_deployed ? '已部署' : '未部署' }}</td></tr>
          <tr><td style="color: var(--text-secondary);">最近检查</td><td>{{ host.last_check || '—' }}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 组件管理 -->
    <div v-else-if="tab === 'components'" class="card">
      <table>
        <thead><tr><th>组件</th><th>状态</th><th>说明</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="c in compActions" :key="c.name">
            <td style="font-weight: 600;">{{ c.label }}</td>
            <td>
              <span class="badge" :class="compInstalled(c.name) ? 'badge-online' : 'badge-unknown'">
                {{ compInstalled(c.name) ? '已安装' : '未安装' }}
              </span>
            </td>
            <td style="font-size: 13px; color: var(--text-secondary);">{{ c.note }}</td>
            <td style="white-space: nowrap;">
              <button v-if="c.install" class="btn btn-sm btn-primary" @click="run(c.install!, '安装/更新')">安装/更新</button>
              <button v-if="c.uninstall && compInstalled(c.name)" class="btn btn-sm btn-danger" @click="run(c.uninstall!, '卸载')">卸载</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- VM 列表 -->
    <div v-else-if="tab === 'vms'" class="card">
      <div style="margin-bottom: 12px;">
        <button class="btn btn-primary" @click="run(() => vmsApi.sync(hostId), 'VM 同步')">同步 VM 列表</button>
      </div>
      <table>
        <thead><tr><th>VMID</th><th>名称</th><th>UUID</th><th>状态</th></tr></thead>
        <tbody>
          <tr v-for="v in vms" :key="v.id">
            <td>{{ v.vmid }}</td>
            <td>{{ v.name || '—' }}</td>
            <td style="font-family: monospace; font-size: 12px;">{{ v.uuid || '—' }}</td>
            <td>{{ v.status }}</td>
          </tr>
          <tr v-if="!vms.length"><td colspan="4" style="text-align: center; color: #888;">暂无 VM 记录，点「同步 VM 列表」</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 任务历史 -->
    <div v-else-if="tab === 'jobs'" class="card">
      <table>
        <thead><tr><th>ID</th><th>类型</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="j in jobs" :key="j.id">
            <td>#{{ j.id }}</td>
            <td>{{ j.kind }}</td>
            <td>{{ jobStatusLabel[j.status] || j.status }}</td>
            <td>{{ j.created_at }}</td>
            <td>
              <router-link class="todo-link" :to="'/jobs'" style="font-size: 13px; color: var(--accent);">详情</router-link>
              <button v-if="['failed','rolled_back','abandoned'].includes(j.status)" class="btn btn-sm btn-secondary"
                @click="run(() => jobsApi.retry(j.id), '重跑')">重跑</button>
            </td>
          </tr>
          <tr v-if="!jobs.length"><td colspan="5" style="text-align: center; color: #888;">暂无任务</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 回滚操作 -->
    <div v-else-if="tab === 'rollback'" class="card">
      <h3 style="margin-bottom: 12px;">母机优化回滚（恢复到上次备份）</h3>
      <div style="display: flex; gap: 8px;">
        <button v-if="compInstalled('nosub')" class="btn btn-sm btn-danger"
          @click="run(() => optimizeApi.rollback(hostId, 'nosub'), '回滚初始化')">回滚一键初始化</button>
        <button v-if="compInstalled('optimize')" class="btn btn-sm btn-danger"
          @click="run(() => optimizeApi.rollback(hostId, 'optimize'), '回滚优化')">回滚参数优化</button>
        <span v-if="!compInstalled('nosub') && !compInstalled('optimize')" style="color: #888;">无可回滚的优化组件</span>
      </div>
      <p style="margin-top: 12px; font-size: 13px; color: var(--text-secondary);">
        失败任务的步骤级回滚由作业器自动执行；此处为手动触发的组件级回滚。
      </p>
    </div>
  </div>
</template>

<style scoped>
.notice-ok { padding: 8px 12px; background: #dcfce7; border-radius: 6px; }
.notice-err { padding: 8px 12px; background: #fee2e2; border-radius: 6px; }
</style>
