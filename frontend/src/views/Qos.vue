<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { qosApi, hostsApi } from '../api'

const route = useRoute()
const tab = ref<string>(
  ['policies', 'templates', 'events', 'nodes', 'access'].includes(route.query.tab as string)
    ? (route.query.tab as string) : 'nodes')
watch(() => route.query.tab, (t) => {
  if (t && ['policies', 'templates', 'events', 'nodes', 'access'].includes(t as string)) {
    tab.value = t as string
    if (t === 'events') loadEvents()
  }
})
const hosts = ref<any[]>([])
const nodes = ref<any[]>([])
const templates = ref<any[]>([])
const policies = ref<any[]>([])
const events = ref<any[]>([])
const clusters = ref<any[]>([])
const loading = ref(true)
const notice = ref<{ ok: boolean; text: string } | null>(null)

const newPolicy = ref<{ host_id: number | null; vmid: string; origin: string; initial_mbps: number; net2_mbps: number | null }>(
  { host_id: null, vmid: '', origin: 'domestic', initial_mbps: 0, net2_mbps: null })
const newTemplate = ref({ name: '', config: '' })
const showTemplateForm = ref(false)
const eventFilter = ref<{ host_id: number | null; vmid: string }>({ host_id: null, vmid: '' })
const tokenResult = ref<{ host_id: number; purpose: string; token: string } | null>(null)
const tokenPanel = ref<{ host_id: number; tokens: any[] } | null>(null)

const hostMap = computed(() => {
  const m: Record<number, string> = {}
  hosts.value.forEach((h: any) => { m[h.id] = h.name })
  return m
})

onMounted(loadAll)

async function loadAll() {
  loading.value = true
  try {
    const [h, n, t, p, c] = await Promise.all([
      hostsApi.list(), qosApi.nodes(), qosApi.templates(), qosApi.policies(), qosApi.clusters(),
    ])
    if (h.ok) hosts.value = h.data
    if (n.ok) nodes.value = n.data
    if (t.ok) templates.value = t.data
    if (p.ok) policies.value = p.data
    if (c.ok) clusters.value = c.data
  } finally {
    loading.value = false
  }
}

function flash(ok: boolean, text: string) {
  notice.value = { ok, text }
  setTimeout(() => { notice.value = null }, 5000)
}

async function savePolicy() {
  const p = newPolicy.value
  if (!p.host_id || !p.vmid) { flash(false, '请选择主机并填写 VMID'); return }
  const res = await qosApi.savePolicy({
    host_id: p.host_id, vmid: p.vmid, origin: p.origin,
    initial_mbps: p.initial_mbps,
    net2_mbps: p.origin === 'domestic' ? p.net2_mbps : null,
    enabled: true,
  })
  if (res.ok) { newPolicy.value.vmid = ''; loadAll() }
  flash(res.ok, res.ok ? '策略已保存（下次快照生效）' : res.error)
}

async function createTemplate() {
  let cfg: any
  try { cfg = JSON.parse(newTemplate.value.config) } catch { flash(false, '配置不是合法 JSON'); return }
  const res = await qosApi.createTemplate({ name: newTemplate.value.name, config: cfg })
  if (res.ok) { newTemplate.value = { name: '', config: '' }; showTemplateForm.value = false; loadAll() }
  flash(res.ok, res.ok ? '模板已创建' : res.error)
}

async function assignTemplate(hostId: number, templateId: number | null) {
  const res = await qosApi.assignTemplate(hostId, templateId)
  flash(res.ok, res.ok ? '已设置节点模板（需下发配置生效）' : res.error)
  if (res.ok) loadAll()
}

async function loadEvents() {
  const params: any = { limit: 200 }
  if (eventFilter.value.host_id) params.host_id = eventFilter.value.host_id
  if (eventFilter.value.vmid) params.vmid = eventFilter.value.vmid
  const res = await qosApi.events(params)
  if (res.ok) events.value = res.data
}

async function issueToken(hostId: number, purpose: string) {
  const res = await qosApi.issueToken(hostId, purpose)
  if (res.ok) {
    tokenResult.value = { host_id: hostId, purpose, token: res.token }
    loadAll()
  } else {
    flash(false, res.error)
  }
}

async function showTokens(hostId: number) {
  const res = await qosApi.tokens(hostId)
  if (res.ok) tokenPanel.value = { host_id: hostId, tokens: res.data }
}

async function action(fn: (id: number) => Promise<any>, hostId: number, label: string) {
  const res = await fn(hostId)
  flash(res.ok, res.ok ? `${label}任务已创建（见任务页）` : res.error)
}

const statusLabel: Record<string, string> = {
  fresh: '正常（快照拉取中）',
  degraded: '降级（有异常记录）',
  stale: '停滞（超时未拉取）',
}
const purposeLabel: Record<string, string> = { snapshot: '快照', report: '上报', intl: '国际站' }
</script>

<template>
  <div>
    <div class="page-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
      <div>
        <h1>带宽 QoS</h1>
        <p class="subtitle">vmqos 动态限速：策略 → 快照 → 节点拉取。PVE 网卡限速为双向同值。</p>
      </div>
    </div>

    <div v-if="notice" :class="notice.ok ? 'notice-ok' : 'notice-err'" style="margin-bottom: 12px;">{{ notice.text }}</div>

    <!-- 节点状态 -->
    <div v-if="tab === 'nodes'" class="card">
      <h3 style="margin-bottom: 12px;">节点状态（快照拉取推断，非 vmqos 主动心跳）</h3>
      <table>
        <thead><tr><th>节点</th><th>地址</th><th>状态</th><th>档位模板</th><th>最近快照</th><th>最近事件</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="n in nodes" :key="n.host_id">
            <td>{{ n.name }}</td>
            <td>{{ n.host }}</td>
            <td><span :class="'status-' + n.status">{{ statusLabel[n.status] || n.status }}</span></td>
            <td>
              <select class="form-input" :value="n.template_id" @change="assignTemplate(n.host_id, ($event.target as any).value ? Number(($event.target as any).value) : null)">
                <option :value="null">默认阶梯</option>
                <option v-for="t in templates" :key="t.id" :value="t.id">{{ t.name }}</option>
              </select>
            </td>
            <td>{{ n.last_snapshot_at || '—' }}</td>
            <td>{{ n.last_report_at || '—' }}</td>
            <td style="white-space: nowrap;">
              <button class="btn btn-sm btn-primary" @click="action(qosApi.install, n.host_id, '安装')">安装</button>
              <button class="btn btn-sm btn-secondary" @click="action(qosApi.configApply, n.host_id, '配置下发')">下发配置</button>
              <button class="btn btn-sm btn-secondary" @click="action(qosApi.status, n.host_id, '状态回采')">状态</button>
              <button class="btn btn-sm btn-secondary" @click="tab = 'access'; showTokens(n.host_id)">Token</button>
              <button class="btn btn-sm btn-secondary" @click="action(qosApi.uninstall, n.host_id, '卸载')">卸载</button>
            </td>
          </tr>
          <tr v-if="!nodes.length"><td colspan="7" style="text-align: center; color: #888;">暂无 QoS 节点——先在下方「Token」签发接入凭据并安装</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 带宽策略 -->
    <div v-if="tab === 'policies'" class="card">
      <h3 style="margin-bottom: 12px;">VM 带宽策略（initial_mbps 为基础速率，0 = 保留记录但跳过限速；国内/国际为双数据来源，国内优先合并）</h3>
      <div style="display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap;">
        <select class="form-input" v-model="newPolicy.host_id" style="width: 160px;">
          <option :value="null">选择主机</option>
          <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.name }}</option>
        </select>
        <input class="form-input" v-model="newPolicy.vmid" placeholder="VMID" style="width: 100px;" />
        <select class="form-input" v-model="newPolicy.origin" style="width: 120px;">
          <option value="domestic">国内源</option>
          <option value="international">国际源</option>
        </select>
        <input class="form-input" type="number" v-model.number="newPolicy.initial_mbps" placeholder="基础速率 Mbps" style="width: 130px;" />
        <input v-if="newPolicy.origin === 'domestic'" class="form-input" type="number" v-model.number="newPolicy.net2_mbps" placeholder="net2 专线 Mbps（可选）" style="width: 170px;" />
        <button class="btn btn-primary" @click="savePolicy">保存策略</button>
      </div>
      <table>
        <thead><tr><th>主机</th><th>VMID</th><th>来源</th><th>基础速率</th><th>net2 专线</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="p in policies" :key="p.id">
            <td>{{ hostMap[p.host_id] || p.host_id }}</td>
            <td>{{ p.vmid }}</td>
            <td>{{ p.origin === 'domestic' ? '国内' : '国际' }}</td>
            <td>{{ p.initial_mbps }} Mbps</td>
            <td>{{ p.net2_mbps ? p.net2_mbps + ' Mbps' : '—' }}</td>
            <td>{{ p.enabled ? '启用' : '停用' }}</td>
            <td>
              <button class="btn btn-sm btn-secondary" @click="qosApi.togglePolicy(p.id).then(loadAll)">{{ p.enabled ? '停用' : '启用' }}</button>
              <button class="btn btn-sm btn-secondary" @click="qosApi.delPolicy(p.id).then(loadAll)">删除</button>
            </td>
          </tr>
          <tr v-if="!policies.length"><td colspan="7" style="text-align: center; color: #888;">暂无策略</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 档位模板 -->
    <div v-if="tab === 'templates'" class="card">
      <h3 style="margin-bottom: 8px;">阶梯档位模板（节点级生效：vmqos 档位配置为节点全局，切换模板后需「下发配置」）</h3>
      <p style="color: #888; margin-bottom: 12px;">使用率持续超阈值 → 升档压缩速率；limits 为各档位相对基础速率的比例。</p>
      <button class="btn btn-primary" style="margin-bottom: 12px;" @click="showTemplateForm = !showTemplateForm">新建模板</button>
      <div v-if="showTemplateForm" style="margin-bottom: 12px;">
        <input class="form-input" v-model="newTemplate.name" placeholder="模板名" style="width: 200px; margin-bottom: 8px;" />
        <textarea class="form-input" v-model="newTemplate.config" rows="8"
          placeholder='{"high_usage_ratio":0.8,"limits":{"0":1.0,"1":0.85,"2":0.7},"raise_rules":[{"stage":1,"seconds":600}],"stage_cap":6}'></textarea>
        <button class="btn btn-primary" style="margin-top: 8px;" @click="createTemplate">校验并创建</button>
      </div>
      <table>
        <thead><tr><th>名称</th><th>档位</th><th>阈值</th><th>来源</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="t in templates" :key="t.id">
            <td>{{ t.name }}</td>
            <td style="font-size: 12px;">{{ Object.entries(t.config?.limits || {}).map(([k, v]) => `${k}:${v}`).join(' ') }}</td>
            <td>{{ t.config?.high_usage_ratio }}</td>
            <td>{{ t.builtin ? '内置' : '自定义' }}</td>
            <td><button v-if="!t.builtin" class="btn btn-sm btn-secondary" @click="qosApi.delTemplate(t.id).then(loadAll)">删除</button></td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 限速事件流 -->
    <div v-if="tab === 'events'" class="card">
      <h3 style="margin-bottom: 12px;">限速事件流（vmqos 上报；同内容 2 分钟内去重）</h3>
      <div style="display: flex; gap: 8px; margin-bottom: 12px;">
        <select class="form-input" v-model="eventFilter.host_id" style="width: 160px;">
          <option :value="null">全部主机</option>
          <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.name }}</option>
        </select>
        <input class="form-input" v-model="eventFilter.vmid" placeholder="VMID" style="width: 100px;" />
        <button class="btn btn-primary" @click="loadEvents">查询</button>
      </div>
      <table>
        <thead><tr><th>时间</th><th>主机</th><th>VMID</th><th>来源</th><th>档位</th><th>限速值</th></tr></thead>
        <tbody>
          <tr v-for="e in events" :key="e.id">
            <td>{{ e.reported_at }}</td>
            <td>{{ e.host }}</td>
            <td>{{ e.vmid }}</td>
            <td>{{ e.origin === 'domestic' ? '国内' : '国际' }}</td>
            <td>{{ e.stage === 0 ? '恢复（0 档）' : e.stage }}</td>
            <td>{{ e.limit_mbps != null ? e.limit_mbps + ' Mbps' : '—' }}</td>
          </tr>
          <tr v-if="!events.length"><td colspan="6" style="text-align: center; color: #888;">暂无事件</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 快照 API 接入 -->
    <div v-if="tab === 'access'" class="card">
      <h3 style="margin-bottom: 8px;">快照 API 接入（vmqos 节点凭据签发与轮换）</h3>
      <p style="color: #888; margin-bottom: 12px;">
        节点 vmqos 配置中的接入地址：<code>平台地址/api/v1/vmqos/snapshot</code>（快照）、<code>平台地址/api/v1/vmqos/qos</code>（上报）。
        轮换采用重叠期：新 token 签发后旧 token 仍可用，「下发配置」成功后旧 token 自动撤销。
      </p>
      <div style="margin-bottom: 12px;">
        <select class="form-input" style="width: 200px;" @change="showTokens(Number(($event.target as any).value))">
          <option value="">选择主机管理 token</option>
          <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.name }}（{{ h.host }}）</option>
        </select>
      </div>

      <div v-if="tokenPanel">
        <h4>接入 Token — {{ hostMap[tokenPanel.host_id] }}</h4>
        <table>
          <thead><tr><th>用途</th><th>状态</th><th>签发时间</th><th>最近使用</th></tr></thead>
          <tbody>
            <tr v-for="t in tokenPanel.tokens" :key="t.id">
              <td>{{ purposeLabel[t.purpose] || t.purpose }}</td>
              <td>{{ t.status === 'active' ? '生效' : '轮换中（下次配置下发后撤销）' }}</td>
              <td>{{ t.created_at }}</td>
              <td>{{ t.last_used_at || '—' }}</td>
            </tr>
            <tr v-if="!tokenPanel.tokens.length"><td colspan="4" style="text-align: center; color: #888;">尚未签发</td></tr>
          </tbody>
        </table>
        <div style="margin-top: 8px;">
          <button class="btn btn-sm btn-secondary" @click="issueToken(tokenPanel.host_id, 'snapshot')">签发/轮换快照 token</button>
          <button class="btn btn-sm btn-secondary" @click="issueToken(tokenPanel.host_id, 'report')">签发/轮换上报 token</button>
          <button class="btn btn-sm btn-secondary" @click="issueToken(tokenPanel.host_id, 'intl')">签发/轮换国际站 token</button>
        </div>
      </div>

      <div v-if="tokenResult" class="card" style="margin-top: 12px; background: #fff8e6;">
        <h4>新 token（{{ purposeLabel[tokenResult.purpose] }}）——仅此一次显示，请立即复制：</h4>
        <code style="word-break: break-all;">{{ tokenResult.token }}</code>
        <div style="margin-top: 8px;"><button class="btn btn-sm btn-secondary" @click="tokenResult = null">我已保存</button></div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.status-fresh { color: #16a34a; }
.status-degraded { color: #d97706; }
.status-stale { color: #dc2626; }
.notice-ok { padding: 8px 12px; background: #dcfce7; border-radius: 6px; }
.notice-err { padding: 8px 12px; background: #fee2e2; border-radius: 6px; }
</style>
