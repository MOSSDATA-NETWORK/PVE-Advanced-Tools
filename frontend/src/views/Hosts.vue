<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { hostsApi, scansApi, hostkeyApi, vmsApi } from '../api'

const hosts = ref<any[]>([])
const loading = ref(true)
const showModal = ref(false)
const editHost = ref<any>(null)
const form = ref({ name: '', host: '', port: 22, username: 'root', auth_type: 'password', password: '', ssh_key_content: '', api_token: '' })
const formError = ref('')
const keyDragOver = ref(false)
const keyFileInput = ref<HTMLInputElement | null>(null)
const testing = ref<number | null>(null)
const scanning = ref(false)
const deploying = ref<number | null>(null)

onMounted(loadHosts)

async function loadHosts() {
  loading.value = true
  try {
    const res = await hostsApi.list()
    if (res.ok) hosts.value = res.data
  } finally {
    loading.value = false
  }
}

function openAdd() {
  editHost.value = null
  formError.value = ''
  form.value = { name: '', host: '', port: 22, username: 'root', auth_type: 'password', password: '', ssh_key_content: '', api_token: '' }
  showModal.value = true
}

function openEdit(h: any) {
  editHost.value = h
  formError.value = ''
  form.value = { name: h.name, host: h.host, port: h.port, username: h.username, auth_type: h.auth_type || 'password', password: '', ssh_key_content: '', api_token: '' }
  showModal.value = true
}

async function saveHost() {
  formError.value = ''
  if (!form.value.name.trim()) { formError.value = '请填写主机名称'; return }
  if (!form.value.host.trim()) { formError.value = '请填写主机地址（IP 或域名）'; return }
  if (!form.value.username.trim()) { formError.value = '请填写 SSH 用户名'; return }
  const p = Number(form.value.port)
  if (!p || p < 1 || p > 65535) { formError.value = '端口必须是 1-65535 的数字'; return }
  if (form.value.auth_type === 'password' && !editHost.value && !form.value.password) {
    formError.value = '密码认证方式需要填写 SSH 密码'; return
  }
  if (form.value.auth_type === 'ssh_key' && !editHost.value && !form.value.ssh_key_content) {
    formError.value = '私钥认证方式需要上传或粘贴 SSH 私钥'; return
  }
  if (form.value.auth_type === 'api_token' && !editHost.value && !form.value.api_token) {
    formError.value = 'API Token 认证方式需要填写 PVE API Token'; return
  }

  const data: any = { ...form.value }
  if (!data.password) delete data.password
  if (!data.ssh_key_content) delete data.ssh_key_content
  if (!data.api_token) delete data.api_token

  try {
    if (editHost.value) {
      await hostsApi.update(editHost.value.id, data)
    } else {
      await hostsApi.create(data)
    }
  } catch (e: any) {
    formError.value = e.response?.data?.error || '保存失败，请检查网络或稍后重试'
    return
  }
  showModal.value = false
  loadHosts()
}

async function deleteHost(id: number) {
  if (!confirm('确定删除此主机？')) return
  await hostsApi.delete(id)
  loadHosts()
}

async function testHost(id: number) {
  testing.value = id
  try {
    const res = await hostsApi.test(id)
    alert(res.message || res.error || '测试完成')
    loadHosts()
  } finally {
    testing.value = null
  }
}

async function deployAgent(id: number) {
  deploying.value = id
  try {
    const res = await hostsApi.deploy(id)
    alert(res.message || res.error)
    loadHosts()
  } finally {
    deploying.value = null
  }
}

// SSH 指纹确认（TOFU）
const confirming = ref<number | null>(null)
const confirmFingerprint = ref<{ id: number; fingerprint: string; changed: boolean } | null>(null)

async function scanHostkey(id: number) {
  confirming.value = id
  try {
    const res = await hostkeyApi.scan(id)
    if (res.ok) {
      if (res.warning) alert(res.warning)
      confirmFingerprint.value = { id, fingerprint: res.data.fingerprint, changed: !!res.data.changed }
    } else {
      alert(res.error || '指纹抓取失败')
    }
  } finally {
    confirming.value = null
  }
}

async function confirmHostkey() {
  const target = confirmFingerprint.value
  if (!target) return
  confirmFingerprint.value = null
  confirming.value = target.id
  try {
    // 携带用户已核对的指纹做条件确认，防并发重扫替换
    const res = await hostkeyApi.confirm(target.id, target.fingerprint)
    showNotice(res.ok, res.message || res.error || '指纹确认完成')
    loadHosts()
  } finally {
    confirming.value = null
  }
}

async function syncVms(id: number) {
  const res = await vmsApi.sync(id)
  showNotice(res.ok, res.ok ? `VM 清单已同步：共 ${res.data.total} 台，新增 ${res.data.new}，重绑 ${res.data.rebound}，删除 ${res.data.deleted}` : (res.error || '同步失败'))
}

const notice = ref<{ ok: boolean; text: string } | null>(null)
let noticeTimer: ReturnType<typeof setTimeout> | null = null
function showNotice(ok: boolean, text: string) {
  notice.value = { ok, text }
  if (noticeTimer) clearTimeout(noticeTimer)
  noticeTimer = setTimeout(() => (notice.value = null), 6000)
}

async function scanAll() {
  scanning.value = true
  try {
    const res = await scansApi.create()
    if (res.ok) showNotice(true, '扫描已启动，进入「扫描记录」可查看实时进度')
    else showNotice(false, res.error || '扫描启动失败')
  } catch (e: any) {
    showNotice(false, e.response?.data?.error || '扫描启动失败')
  } finally { scanning.value = false }
}

async function scanHost(hostId: number) {
  scanning.value = true
  try {
    const res = await scansApi.create(hostId)
    if (res.ok) showNotice(true, '扫描已启动，进入「扫描记录」可查看实时进度')
    else showNotice(false, res.error || '扫描启动失败')
  } catch (e: any) {
    showNotice(false, e.response?.data?.error || '扫描启动失败')
  } finally { scanning.value = false }
}

function authTypeLabel(t: string) {
  const m: Record<string, string> = { password: '密码', ssh_key: 'SSH Key', api_token: 'API Token' }
  return m[t] || t
}

// SSH Key drag & drop
function onKeyDragOver(e: DragEvent) {
  e.preventDefault()
  keyDragOver.value = true
}

function onKeyDragLeave() {
  keyDragOver.value = false
}

function onKeyDrop(e: DragEvent) {
  e.preventDefault()
  keyDragOver.value = false
  const file = e.dataTransfer?.files?.[0]
  if (file) readKeyFile(file)
}

function onKeyFileSelect(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) readKeyFile(file)
  input.value = ''
}

function readKeyFile(file: File) {
  const reader = new FileReader()
  reader.onload = (e) => {
    const content = e.target?.result as string
    if (content.includes('PRIVATE KEY') || content.includes('OPENSSH')) {
      form.value.ssh_key_content = content.trim()
    } else {
      alert('文件内容不是有效的 SSH 私钥')
    }
  }
  reader.readAsText(file)
}

function triggerKeyUpload() {
  keyFileInput.value?.click()
}

function clearKey() {
  form.value.ssh_key_content = ''
}
</script>

<template>
  <div>
    <div class="page-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
      <div>
        <h1 class="page-title">主机管理</h1>
        <p class="page-subtitle">管理 PVE 宿主机，添加后需确认 SSH 指纹才会部署组件</p>
      </div>
      <div style="display: flex; gap: 12px;">
        <button class="btn btn-secondary" @click="scanAll" :disabled="scanning">{{ scanning ? '扫描中...' : '扫描全部' }}</button>
        <button class="btn btn-primary" @click="openAdd">+ 添加主机</button>
      </div>
    </div>

    <!-- 操作通知条 -->
    <div v-if="notice" style="margin-bottom: 16px; display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-radius: 12px;"
      :style="{ background: notice.ok ? 'rgba(52,199,89,0.08)' : 'rgba(255,59,48,0.08)', border: '1px solid ' + (notice.ok ? 'rgba(52,199,89,0.2)' : 'rgba(255,59,48,0.2)') }">
      <span style="font-size: 18px;">{{ notice.ok ? '✅' : '❌' }}</span>
      <span style="font-size: 14px; flex: 1;">{{ notice.text }}</span>
      <button class="btn btn-sm btn-secondary" @click="notice = null">关闭</button>
    </div>

    <div class="card">
      <div v-if="loading" style="text-align: center; padding: 40px;"><div class="spinner" style="margin: 0 auto;"></div></div>
      <div v-else-if="hosts.length === 0" class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="48" height="48"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
        <p>还没有添加主机</p>
        <button class="btn btn-primary" @click="openAdd">添加第一台 PVE</button>
      </div>
      <div v-else class="table-container">
        <table>
          <thead>
            <tr><th>名称</th><th>地址</th><th>接入方式</th><th>状态</th><th>指纹 / PVE</th><th>Agent</th><th style="text-align: right;">操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="h in hosts" :key="h.id">
              <td style="font-weight: 600;">{{ h.name }}</td>
              <td><code style="font-size: 13px;">{{ h.host }}:{{ h.port }}</code></td>
              <td>{{ authTypeLabel(h.auth_type) }}</td>
              <td><span :class="['badge', `badge-${h.status}`]">{{ h.status }}</span></td>
              <td>
                <div style="display: flex; flex-direction: column; gap: 4px;">
                  <span v-if="h.host_key_status === 'confirmed'" class="badge badge-online" :title="h.host_key_fingerprint">指纹已确认</span>
                  <span v-else-if="h.host_key_fingerprint" class="badge badge-confirmed" :title="h.host_key_fingerprint">待确认指纹</span>
                  <span v-else class="badge badge-unknown">未抓取指纹</span>
                  <span v-if="h.pve_version" style="font-size: 11px; color: var(--text-tertiary);">{{ h.pve_version.split(' ')[0] }}</span>
                </div>
              </td>
              <td>
                <span v-if="h.agent_deployed" class="badge badge-online">已部署</span>
                <span v-else class="badge badge-unknown">未部署</span>
              </td>
              <td style="text-align: right;">
                <div style="display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap;">
                  <button v-if="h.host_key_status !== 'confirmed'" class="btn btn-sm btn-primary" @click="scanHostkey(h.id)" :disabled="confirming === h.id">
                    {{ confirming === h.id ? '处理中...' : (h.host_key_fingerprint ? '确认指纹' : '抓取指纹') }}
                  </button>
                  <button class="btn btn-sm btn-secondary" @click="syncVms(h.id)">同步VM</button>
                  <button class="btn btn-sm btn-secondary" @click="scanHost(h.id)" :disabled="scanning">扫描</button>
                  <button class="btn btn-sm btn-secondary" @click="testHost(h.id)" :disabled="testing === h.id">
                    {{ testing === h.id ? '测试中...' : '测试连接' }}
                  </button>
                  <button v-if="!h.agent_deployed" class="btn btn-sm btn-secondary" @click="deployAgent(h.id)" :disabled="deploying === h.id">
                    {{ deploying === h.id ? '部署中...' : '部署Agent' }}
                  </button>
                  <button class="btn btn-sm btn-secondary" @click="openEdit(h)">编辑</button>
                  <button class="btn btn-sm btn-danger" @click="deleteHost(h.id)">删除</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Add/Edit Modal -->
    <div v-if="showModal" class="modal-overlay" @click.self="showModal = false">
      <div class="modal">
        <div class="modal-header">{{ editHost ? '编辑主机' : '添加主机' }}</div>
        <div class="modal-body">
          <div class="form-group">
            <label class="form-label">名称</label>
            <input class="form-input" v-model="form.name" placeholder="如：pve-node1" />
          </div>
          <div class="form-group">
            <label class="form-label">IP 地址</label>
            <input class="form-input" v-model="form.host" placeholder="192.168.1.100 或 hv.example.com" />
          </div>

          <div class="form-group">
            <label class="form-label">接入方式</label>
            <select class="form-input" v-model="form.auth_type">
              <option value="password">SSH 密码</option>
              <option value="ssh_key">SSH 私钥</option>
              <option value="api_token">PVE API Token</option>
            </select>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
            <div class="form-group">
              <label class="form-label">SSH 端口</label>
              <input class="form-input" type="number" v-model.number="form.port" />
            </div>
            <div class="form-group">
              <label class="form-label">用户名</label>
              <input class="form-input" v-model="form.username" />
            </div>
          </div>

          <div v-if="form.auth_type === 'password'" class="form-group">
            <label class="form-label">密码 {{ editHost ? '(留空不修改)' : '' }}</label>
            <input class="form-input" type="password" v-model="form.password" placeholder="SSH 密码" />
          </div>

          <div v-if="form.auth_type === 'ssh_key'" class="form-group">
            <label class="form-label">SSH 私钥</label>
            <!-- 已上传状态 -->
            <div v-if="form.ssh_key_content" class="key-uploaded">
              <div class="key-uploaded-info">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="color:var(--green)"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                <span>私钥已加载 ({{ form.ssh_key_content.split('\n').length }} 行)</span>
              </div>
              <div class="key-uploaded-actions">
                <button class="btn btn-sm btn-secondary" @click="form.ssh_key_content = form.ssh_key_content ? '' : ''">查看</button>
                <button class="btn btn-sm btn-danger" @click="clearKey">删除</button>
              </div>
            </div>
            <!-- 上传区域 -->
            <div v-else
              class="key-dropzone"
              :class="{ 'key-dropzone-active': keyDragOver }"
              @dragover="onKeyDragOver"
              @dragleave="onKeyDragLeave"
              @drop="onKeyDrop"
              @click="triggerKeyUpload"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="32" height="32" style="color:var(--text-tertiary);margin-bottom:8px;">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
              <div style="font-size:14px;font-weight:500;margin-bottom:4px;">拖拽私钥文件到此处</div>
              <div style="font-size:12px;color:var(--text-secondary);">或点击选择文件</div>
              <input ref="keyFileInput" type="file" accept=".pem,.key,id_rsa,id_ed25519,*" style="display:none" @change="onKeyFileSelect" />
            </div>
            <!-- 粘贴区域 -->
            <div style="margin-top:8px;">
              <details class="key-paste-details">
                <summary style="font-size:12px;color:var(--accent);cursor:pointer;">或粘贴私钥内容</summary>
                <textarea class="form-input" v-model="form.ssh_key_content" rows="6"
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
粘贴完整私钥内容...
-----END OPENSSH PRIVATE KEY-----"
                  style="margin-top:8px;font-family:monospace;font-size:12px;resize:vertical;"></textarea>
              </details>
            </div>
            <div style="font-size:11px;color:var(--text-tertiary);margin-top:6px;">
              私钥将加密存储在平台服务器上，用于 SSH 连接 PVE 主机
            </div>
          </div>

          <div v-if="form.auth_type === 'api_token'" class="form-group">
            <label class="form-label">PVE API Token</label>
            <input class="form-input" v-model="form.api_token" placeholder="user@pve!tokenid=secret" />
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
              格式：用户名@pve!token名=token值，需要在 PVE 数据中心 → API Token 中创建
            </div>
          </div>
        </div>
        <div v-if="formError" style="padding: 0 20px 4px;">
          <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;border-radius:10px;background:rgba(255,59,48,0.08);border:1px solid rgba(255,59,48,0.2);">
            <span style="font-size:15px;">⚠️</span>
            <span style="font-size:13px;color:var(--red);">{{ formError }}</span>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showModal = false">取消</button>
          <button class="btn btn-primary" @click="saveHost">保存</button>
        </div>
      </div>
    </div>

    <!-- SSH 指纹确认弹窗 -->
    <div v-if="confirmFingerprint" class="modal-overlay" @click.self="confirmFingerprint = null">
      <div class="modal" style="max-width: 480px;">
        <div class="modal-header">确认 SSH 主机指纹</div>
        <div class="modal-body">
          <p style="font-size: 14px; color: var(--text-secondary); line-height: 1.8; margin: 0 0 12px;">
            请通过带外渠道（如 PVE 控制台 <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>）核对该指纹。
            确认后平台将固定该指纹，之后所有连接都会校验，防止中间人攻击。
          </p>
          <div v-if="confirmFingerprint.changed" style="padding: 10px 14px; margin-bottom: 12px; border-radius: 10px; background: rgba(255,59,48,0.06); border: 1px solid rgba(255,59,48,0.2); font-size: 13px; color: var(--red);">
            注意：本次抓取的指纹与之前已确认的值不一致，请确认主机未被替换或劫持后再继续。
          </div>
          <code style="display: block; font-size: 13px; padding: 12px; background: var(--bg-secondary); border-radius: 8px; word-break: break-all;">{{ confirmFingerprint.fingerprint }}</code>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="confirmFingerprint = null">取消</button>
          <button class="btn btn-primary" @click="confirmHostkey">指纹正确，确认并部署</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.key-dropzone {
  border: 2px dashed var(--border);
  border-radius: 12px;
  padding: 24px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  flex-direction: column;
  align-items: center;
}
.key-dropzone:hover,
.key-dropzone-active {
  border-color: var(--accent);
  background: rgba(0,122,255,0.04);
}
.key-uploaded {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: rgba(52,199,89,0.08);
  border: 1px solid rgba(52,199,89,0.2);
  border-radius: 10px;
}
.key-uploaded-info {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 500;
}
.key-uploaded-actions {
  display: flex;
  gap: 8px;
}
.key-paste-details summary::marker {
  content: '';
}
.key-paste-details summary::before {
  content: '▸ ';
}
.key-paste-details[open] summary::before {
  content: '▾ ';
}
</style>
