<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { netguardApi, hostsApi } from '../api'

const ports = ref<any[]>([])
const domains = ref<any[]>([])
const hosts = ref<any[]>([])
const scope = ref<Record<number, boolean>>({})
const whitelist = ref<any[]>([])
const components = ref<Record<string, any>>({})
const loading = ref(true)
const notice = ref<{ ok: boolean; text: string } | null>(null)

const newPort = ref({ name: '', ports: '' })
const newDomain = ref('')
const importText = ref('')
const showImport = ref(false)
const newWl = ref<{ host_id: number | null; vmid: string }>({ host_id: null, vmid: '' })

const hostMap = computed(() => {
  const m: Record<number, string> = {}
  hosts.value.forEach((h: any) => { m[h.id] = h.name })
  return m
})

onMounted(loadAll)

async function loadAll() {
  loading.value = true
  try {
    const [p, d, h, s, st] = await Promise.all([
      netguardApi.listPorts(), netguardApi.listDomains(), hostsApi.list(),
      netguardApi.getScope(), api200('/netguard/status'),
    ])
    if (p.ok) ports.value = p.data
    if (d.ok) domains.value = d.data
    if (h.ok) hosts.value = h.data
    if (s.ok) {
      const m: Record<number, boolean> = {}
      s.scope.forEach((r: any) => { m[r.host_id] = r.enabled })
      scope.value = m
      whitelist.value = s.whitelist
    }
    if (st?.ok) components.value = st.components
  } finally {
    loading.value = false
  }
}

async function api200(path: string) {
  try {
    const r = await fetch(`/api${path}`)
    return await r.json()
  } catch { return null }
}

function showNotice(ok: boolean, text: string) {
  notice.value = { ok, text }
  setTimeout(() => (notice.value = null), 6000)
}

async function addPort() {
  const res = await netguardApi.addPort(newPort.value)
  showNotice(res.ok, res.ok ? '端口条目已添加（下发后生效）' : res.error)
  if (res.ok) { newPort.value = { name: '', ports: '' }; loadAll() }
}

async function addDomain() {
  if (!newDomain.value.trim()) return
  const res = await netguardApi.addDomain({ domain: newDomain.value })
  showNotice(res.ok, res.ok ? '域名已添加（下发后生效）' : res.error)
  if (res.ok) { newDomain.value = ''; loadAll() }
}

async function doImport() {
  const res = await netguardApi.importDomains(importText.value)
  showNotice(res.ok, res.ok ? `导入完成：新增 ${res.added}，跳过 ${res.skipped}` : res.error)
  if (res.ok) { importText.value = ''; showImport.value = false; loadAll() }
}

async function toggleScope(h: any) {
  const enabled = !scope.value[h.id]
  const res = await netguardApi.setScope(h.id, enabled)
  showNotice(res.ok, res.ok ? `${h.name} 已${enabled ? '纳入' : '移出'}管控范围（下发后生效）` : res.error)
  loadAll()
}

async function addWhitelist() {
  if (!newWl.value.host_id || !newWl.value.vmid) return
  const res = await netguardApi.addWhitelist({ host_id: newWl.value.host_id, vmid: Number(newWl.value.vmid) })
  showNotice(res.ok, res.ok ? '白名单已添加（下发后生效）' : res.error)
  if (res.ok) { newWl.value = { host_id: null, vmid: '' }; loadAll() }
}

async function delWhitelistRow(id: number) {
  await netguardApi.delWhitelist(id)
  loadAll()
}

async function deployAll() {
  if (!confirm('将把当前管控配置下发到所有生效主机，继续？')) return
  const res = await netguardApi.deploy()
  if (res.ok) {
    showNotice(true, `已创建 ${res.jobs.length} 个下发任务，详见「任务中心」`)
  } else {
    showNotice(false, res.error || '下发失败')
  }
}

function componentBadge(hostId: number) {
  const c = components.value[String(hostId)]?.netguard
  return c ? '已安装' : '未安装'
}
</script>

<template>
  <div>
    <div class="page-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
      <div>
        <h1 class="page-title">出网管控</h1>
        <p class="page-subtitle">VM 出网端口封堵与域名拦截（SNI/DNS 双通道，IPv4+IPv6），按宿主机生效</p>
      </div>
      <button class="btn btn-primary" @click="deployAll">下发到生效主机</button>
    </div>

    <div v-if="notice" style="margin-bottom: 16px; padding: 12px 16px; border-radius: 12px;"
      :style="{ background: notice.ok ? 'rgba(52,199,89,0.08)' : 'rgba(255,59,48,0.08)', border: '1px solid ' + (notice.ok ? 'rgba(52,199,89,0.2)' : 'rgba(255,59,48,0.2)') }">
      <span style="font-size: 14px;">{{ notice.text }}</span>
    </div>

    <div v-if="loading" style="text-align: center; padding: 40px;"><div class="spinner" style="margin: 0 auto;"></div></div>
    <template v-else>
      <!-- 生效范围 -->
      <div class="card" style="margin-bottom: 16px;">
        <h3 style="margin: 0 0 12px; font-size: 16px;">生效范围（按宿主机）</h3>
        <div class="table-container">
          <table>
            <thead><tr><th>主机</th><th>组件状态</th><th>纳入管控</th></tr></thead>
            <tbody>
              <tr v-for="h in hosts" :key="h.id">
                <td style="font-weight: 600;">{{ h.name }}</td>
                <td><span :class="['badge', componentBadge(h.id) === '已安装' ? 'badge-online' : 'badge-unknown']">{{ componentBadge(h.id) }}</span></td>
                <td>
                  <button class="btn btn-sm" :class="scope[h.id] ? 'btn-primary' : 'btn-secondary'" @click="toggleScope(h)">
                    {{ scope[h.id] ? '已纳入' : '未纳入' }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- 端口封堵 -->
      <div class="card" style="margin-bottom: 16px;">
        <h3 style="margin: 0 0 12px; font-size: 16px;">端口封堵列表</h3>
        <div class="table-container">
          <table>
            <thead><tr><th>名称</th><th>端口（TCP）</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>
              <tr v-for="p in ports" :key="p.id">
                <td>{{ p.name }}<span v-if="p.builtin" style="font-size: 11px; color: var(--text-tertiary);">（内置）</span></td>
                <td><code style="font-size: 12px;">{{ p.ports }}</code></td>
                <td><span :class="['badge', p.enabled ? 'badge-online' : 'badge-unknown']">{{ p.enabled ? '启用' : '停用' }}</span></td>
                <td>
                  <button class="btn btn-sm btn-secondary" @click="netguardApi.togglePort(p.id).then(loadAll)">{{ p.enabled ? '停用' : '启用' }}</button>
                  <button v-if="!p.builtin" class="btn btn-sm btn-danger" style="margin-left: 6px;" @click="netguardApi.delPort(p.id).then(loadAll)">删除</button>
                </td>
              </tr>
              <tr>
                <td><input class="form-input" v-model="newPort.name" placeholder="名称，如 邮件提交" /></td>
                <td><input class="form-input" v-model="newPort.ports" placeholder="25,465 或 6880:6999" /></td>
                <td colspan="2"><button class="btn btn-sm btn-primary" @click="addPort">添加</button></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- 域名拦截 -->
      <div class="card" style="margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h3 style="margin: 0; font-size: 16px;">域名拦截列表</h3>
          <button class="btn btn-sm btn-secondary" @click="showImport = !showImport">批量导入</button>
        </div>
        <div v-if="showImport" style="margin-bottom: 12px;">
          <textarea class="form-input" v-model="importText" rows="4" placeholder="每行一个域名"></textarea>
          <button class="btn btn-sm btn-primary" style="margin-top: 8px;" @click="doImport">导入</button>
        </div>
        <div class="table-container">
          <table>
            <thead><tr><th>域名</th><th>备注</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>
              <tr v-for="d in domains" :key="d.id">
                <td><code style="font-size: 13px;">{{ d.domain }}</code></td>
                <td style="font-size: 13px; color: var(--text-secondary);">{{ d.comment || '-' }}</td>
                <td><span :class="['badge', d.enabled ? 'badge-online' : 'badge-unknown']">{{ d.enabled ? '启用' : '停用' }}</span></td>
                <td>
                  <button class="btn btn-sm btn-secondary" @click="netguardApi.toggleDomain(d.id).then(loadAll)">{{ d.enabled ? '停用' : '启用' }}</button>
                  <button class="btn btn-sm btn-danger" style="margin-left: 6px;" @click="netguardApi.delDomain(d.id).then(loadAll)">删除</button>
                </td>
              </tr>
              <tr>
                <td><input class="form-input" v-model="newDomain" placeholder="example.com" @keyup.enter="addDomain" /></td>
                <td colspan="3"><button class="btn btn-sm btn-primary" @click="addDomain">添加</button></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- VM 白名单 -->
      <div class="card">
        <h3 style="margin: 0 0 12px; font-size: 16px;">VM 白名单豁免（按 VMID，guest 无法伪造）</h3>
        <div class="table-container">
          <table>
            <thead><tr><th>主机</th><th>VMID</th><th>备注</th><th>操作</th></tr></thead>
            <tbody>
              <tr v-for="w in whitelist" :key="w.id">
                <td>{{ hostMap[w.host_id] || '#' + w.host_id }}</td>
                <td style="font-weight: 600;">{{ w.vmid }}</td>
                <td style="font-size: 13px; color: var(--text-secondary);">{{ w.note || '-' }}</td>
                <td><button class="btn btn-sm btn-danger" @click="delWhitelistRow(w.id)">删除</button></td>
              </tr>
              <tr>
                <td>
                  <select class="form-input" v-model="newWl.host_id">
                    <option :value="null">选择主机</option>
                    <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.name }}</option>
                  </select>
                </td>
                <td><input class="form-input" v-model="newWl.vmid" placeholder="100" /></td>
                <td colspan="2"><button class="btn btn-sm btn-primary" @click="addWhitelist">添加</button></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
