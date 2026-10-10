<script setup lang="ts">
import {ref, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {notificationsApi, versionApi, passkeyApi, settingsApi } from '../api'
import { registerPasskey, isWebAuthnSupported } from '../passkey'
import axios from 'axios'
import { generateQrDataUrl } from '../qr'
import { formatTime } from '../time'


const route = useRoute()
const platformUrl = ref('')
const mirrorToken = ref('')
async function loadPlatformSettings() {
  const res = await settingsApi.get()
  if (res.ok) platformUrl.value = res.data.platform_public_url || ''
  if (res.ok) mirrorToken.value = res.data.github_mirror_token || ''
}
async function savePlatformUrl() {
  const res = await settingsApi.put('platform_public_url', platformUrl.value.trim())
  if (res.ok) alert('平台地址已保存')
  else alert(res.error || '保存失败')
}
async function saveMirrorToken() {
  const res = await settingsApi.put('github_mirror_token', mirrorToken.value.trim())
  if (res.ok) alert('镜像 token 已保存')
  else alert(res.error || '保存失败')
}

const tab = ref<string>((route.query.tab as string) || 'account')
watch(() => route.query.tab, t => { if (t) tab.value = t as string })

const router = useRouter()
const notifications = ref<any[]>([])
const loading = ref(true)
const showModal = ref(false)
const editItem = ref<any>(null)
const testing = ref(false)
const notifyType = ref('telegram')

// Version
const currentVersion = ref('')
const updateInfo = ref<any>(null)
const checkingUpdate = ref(false)
const updating = ref(false)
const changelog = ref<any[]>([])
const showChangelog = ref(false)

// Telegram form
const tgForm = ref({ bot_token: '', chat_id: '' })
// WeCom form
const wcForm = ref({ webhook: '' })
const notifyLevel = ref('detected_and_cleaned')

// Account settings
const showPasswordModal = ref(false)
const passwordForm = ref({ old_password: '', new_password: '', confirm_password: '' })
const passwordLoading = ref(false)
const showTotpModal = ref(false)
const totpPassword = ref('')
const totpLoading = ref(false)
const totpSecret = ref('')
const totpUri = ref('')
const totpCode = ref('')
const totpStep = ref(1) // 1=confirm, 2=show secret, 3=verify code
const totpQrDataUrl = ref('')
const passkeySupported = ref(false)
const passkeyLoading = ref(false)
const passkeyRegistered = ref(false)

onMounted(async () => {
  loadPlatformSettings()
  loadNotifications()
  loadVersion()
  passkeySupported.value = isWebAuthnSupported()
  checkPasskeyStatus()
})

async function loadVersion() {
  try {
    const res = await versionApi.current()
    if (res.ok) currentVersion.value = res.version
  } catch {}
}

async function checkUpdate() {
  checkingUpdate.value = true
  try {
    const res = await versionApi.check()
    if (res.ok) {
      updateInfo.value = res.data
    }
  } finally {
    checkingUpdate.value = false
  }
}

async function loadChangelog() {
  try {
    const res = await versionApi.changelog()
    if (res.ok) changelog.value = res.data
  } catch {}
  showChangelog.value = true
}

const updateResult = ref('')
const updateSuccess = ref(false)

async function doUpdate() {
  updating.value = true
  updateResult.value = ''
  updateSuccess.value = false
  try {
    const res = await versionApi.update()
    if (res.ok) {
      updateSuccess.value = true
      updateResult.value = res.message || '更新成功，正在重启...'
      // 等待服务重启后刷新页面
      setTimeout(() => {
        window.location.reload()
      }, 5000)
    } else {
      updateResult.value = res.error || '更新失败'
    }
  } catch (e: any) {
    updateResult.value = e.response?.data?.error || '更新失败'
  } finally {
    updating.value = false
  }
}

async function loadNotifications() {
  loading.value = true
  try {
    const res = await notificationsApi.list()
    if (res.ok) notifications.value = res.data
  } finally {
    loading.value = false
  }
}

function openAdd(type?: string) {
  editItem.value = null
  notifyType.value = type || 'telegram'
  tgForm.value = { bot_token: '', chat_id: '' }
  wcForm.value = { webhook: '' }
  notifyLevel.value = 'detected_and_cleaned'
  showModal.value = true
}

function openEdit(n: any) {
  editItem.value = n
  notifyType.value = n.type
  try {
    const config = JSON.parse(n.config)
    if (n.type === 'telegram') {
      tgForm.value = { bot_token: config.bot_token || '', chat_id: config.chat_id || '' }
    } else {
      wcForm.value = { webhook: config.webhook || '' }
    }
  } catch {}
  notifyLevel.value = n.notify_level || 'detected_and_cleaned'
  showModal.value = true
}

async function saveNotification() {
  const type = editItem.value?.type || notifyType.value
  const config = type === 'telegram' ? JSON.stringify(tgForm.value) : JSON.stringify(wcForm.value)
  const data = { type, enabled: true, config, notify_level: notifyLevel.value }
  if (editItem.value) {
    await notificationsApi.update(editItem.value.id, data)
  } else {
    await notificationsApi.create(data)
  }
  showModal.value = false
  loadNotifications()
}

async function testNotifications() {
  testing.value = true
  try {
    const res = await notificationsApi.test()
    if (res.ok) {
      const msgs = res.data.map((r: any) => `${r.type}: ${r.success ? '✅' : '❌'} ${r.message}`).join('\n')
      alert(msgs || '没有启用的通知')
    }
  } finally {
    testing.value = false
  }
}

function levelLabel(l: string) {
  const m: Record<string, string> = { all: '全部通知', detected_only: '仅新发现', detected_and_cleaned: '新发现 + 已清除', detected_and_confirmed: '新发现 + 持续发现' }
  return m[l] || l
}

function formatDate(d: string) {
  return formatTime(d)
}

// Account: Change Password
function openChangePassword() {
  passwordForm.value = { old_password: '', new_password: '', confirm_password: '' }
  showPasswordModal.value = true
}

async function doChangePassword() {
  if (passwordForm.value.new_password.length < 8) {
    alert('新密码至少8位')
    return
  }
  if (passwordForm.value.new_password !== passwordForm.value.confirm_password) {
    alert('两次密码不一致')
    return
  }
  passwordLoading.value = true
  try {
    const res = await axios.post('/api/auth/password', {
      old_password: passwordForm.value.old_password,
      new_password: passwordForm.value.new_password,
    })
    if (res.data.ok) {
      alert('密码已修改，请重新登录')
      showPasswordModal.value = false
      router.push('/login')
    } else {
      alert(res.data.error)
    }
  } catch (e: any) {
    alert(e.response?.data?.error || '修改失败')
  } finally {
    passwordLoading.value = false
  }
}

// Account: Reset TOTP
function openResetTotp() {
  totpPassword.value = ''
  totpSecret.value = ''
  totpUri.value = ''
  totpCode.value = ''
  totpStep.value = 1
  showTotpModal.value = true
}

async function doResetTotpStep1() {
  totpLoading.value = true
  try {
    const res = await axios.post('/api/auth/reset-totp', { password: totpPassword.value })
    if (res.data.ok) {
      totpSecret.value = res.data.totp_secret
      totpUri.value = res.data.totp_uri
      totpQrDataUrl.value = await generateQrDataUrl(res.data.totp_uri)
      totpStep.value = 2
    } else {
      alert(res.data.error)
    }
  } catch (e: any) {
    alert(e.response?.data?.error || '操作失败')
  } finally {
    totpLoading.value = false
  }
}

async function doResetTotpStep3() {
  totpLoading.value = true
  try {
    const res = await axios.post('/api/auth/verify-totp', { code: totpCode.value })
    if (res.data.ok) {
      alert('TOTP 已重新绑定')
      showTotpModal.value = false
    } else {
      alert(res.data.error)
    }
  } catch (e: any) {
    alert(e.response?.data?.error || '验证失败')
  } finally {
    totpLoading.value = false
  }
}

async function doDisableTotp() {
  if (!confirm('确定禁用 TOTP？禁用后登录将不再需要二次验证。')) return
  totpLoading.value = true
  try {
    const res = await axios.post('/api/auth/disable-totp', { password: totpPassword.value })
    if (res.data.ok) {
      alert('TOTP 已禁用')
      showTotpModal.value = false
    } else {
      alert(res.data.error)
    }
  } catch (e: any) {
    alert(e.response?.data?.error || '操作失败')
  } finally {
    totpLoading.value = false
  }
}

function logout() {
  axios.post('/api/auth/logout').finally(() => router.push('/login'))
}

// Passkey
async function checkPasskeyStatus() {
  try {
    const res = await passkeyApi.hasPasskey('')
    if (res.ok) passkeyRegistered.value = res.has_passkey
  } catch {}
}

async function registerPasskeyAction() {
  passkeyLoading.value = true
  try {
    // 1. 获取注册挑战
    const startRes = await passkeyApi.registerStart()
    if (!startRes.ok) {
      alert(startRes.error)
      return
    }

    // 2. 调用浏览器 WebAuthn API
    const credential = await registerPasskey({
      challenge: startRes.challenge,
      rp: startRes.rp,
      user: startRes.user,
      excludeCredentials: startRes.excludeCredentials,
    })

    // 3. 发送到服务器验证
    const finishRes = await passkeyApi.registerFinish(credential)
    if (finishRes.ok) {
      alert('Passkey 注册成功！')
      passkeyRegistered.value = true
    } else {
      alert(finishRes.error || '注册失败')
    }
  } catch (e: any) {
    if (e.name === 'NotAllowedError') {
      alert('用户取消了 Passkey 注册')
    } else {
      alert(e.message || '注册失败')
    }
  } finally {
    passkeyLoading.value = false
  }
}

async function deletePasskey() {
  if (!confirm('确定删除 Passkey？删除后将无法使用 Passkey 登录。')) return
  passkeyLoading.value = true
  try {
    const res = await passkeyApi.delete()
    if (res.ok) {
      alert('Passkey 已删除')
      passkeyRegistered.value = false
    } else {
      alert(res.error)
    }
  } finally {
    passkeyLoading.value = false
  }
}
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">设置</h1>
        <p class="page-subtitle">系统设置与账户管理</p>
      </div>
    </div>

    <!-- Account Settings -->

    <div class="card" v-if="tab === 'account'" style="margin-bottom: 16px;">
      <div class="card-header">
        <h3 id="account">账户设置</h3>
      </div>
      <div class="settings-grid">
        <div class="settings-item" @click="openChangePassword">
          <div class="settings-item-icon" style="background: rgba(0,122,255,0.1); color: var(--accent);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
          </div>
          <div>
            <div class="settings-item-title">修改密码</div>
            <div class="settings-item-desc">更改登录密码</div>
          </div>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="margin-left:auto;color:var(--text-tertiary)"><polyline points="9 18 15 12 9 6"/></svg>
        </div>

        <div class="settings-item" @click="openResetTotp">
          <div class="settings-item-icon" style="background: rgba(175,82,222,0.1); color: var(--purple);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
          </div>
          <div>
            <div class="settings-item-title">TOTP 身份验证器</div>
            <div class="settings-item-desc">重新绑定或禁用二次验证</div>
          </div>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="margin-left:auto;color:var(--text-tertiary)"><polyline points="9 18 15 12 9 6"/></svg>
        </div>

        <div v-if="passkeySupported" class="settings-item" @click="passkeyRegistered ? deletePasskey() : registerPasskeyAction()">
          <div class="settings-item-icon" style="background: rgba(52,199,89,0.1); color: var(--green);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
          </div>
          <div style="flex: 1;">
            <div class="settings-item-title">Passkey</div>
            <div class="settings-item-desc">{{ passkeyRegistered ? '已注册，点击管理' : '使用指纹或面容快速登录' }}</div>
          </div>
          <span v-if="passkeyRegistered" class="badge badge-online">已注册</span>
          <span v-else-if="passkeyLoading" class="spinner" style="width:16px;height:16px;border-width:2px;"></span>
          <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="color:var(--text-tertiary)"><polyline points="9 18 15 12 9 6"/></svg>
        </div>
        <div v-else class="settings-item" style="opacity:0.5;cursor:default;">
          <div class="settings-item-icon" style="background: rgba(52,199,89,0.1); color: var(--green);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
          </div>
          <div>
            <div class="settings-item-title">Passkey</div>
            <div class="settings-item-desc">浏览器不支持 WebAuthn</div>
          </div>
        </div>

        <div class="settings-item" @click="logout" style="border: 1px solid rgba(255,59,48,0.2);">
          <div class="settings-item-icon" style="background: rgba(255,59,48,0.1); color: var(--red);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          </div>
          <div>
            <div class="settings-item-title" style="color:var(--red)">退出登录</div>
            <div class="settings-item-desc">退出当前账户</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Version Card -->
        <div class="card" style="margin-bottom: 16px;">
      <h3 style="margin: 0 0 12px; font-size: 16px;">平台设置</h3>
      <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
        <label style="font-size: 14px; color: var(--text-secondary);">节点可达的平台地址（platform_public_url）</label>
        <input class="form-input" v-model="platformUrl" placeholder="https://panel.example.com" style="width: 320px;" />
        <button class="btn btn-primary" @click="savePlatformUrl">保存</button>
      </div>
      <p style="font-size: 13px; color: var(--text-secondary); margin-top: 8px;">
        下发 vmqos 配置前必填；节点将通过该地址拉取快照与上报限速事件。
      </p>
      <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 12px;">
        <label style="font-size: 14px; color: var(--text-secondary);">GitHub 镜像 token（vmqos 为私有仓库时，节点经平台代理下载）</label>
        <input class="form-input" type="password" v-model="mirrorToken" placeholder="ghp_...（不修改请留 ***）" style="width: 320px;" />
        <button class="btn btn-secondary" @click="saveMirrorToken">保存</button>
      </div>
    </div>

<div class="card" v-if="tab === 'about'" style="margin-bottom: 16px;">
      <div class="card-header">
        <h3 id="about">版本信息</h3>
      </div>
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div>
          <div style="font-size: 28px; font-weight: 700;">PVE Advanced Tools <span style="color: var(--accent);">v{{ currentVersion }}</span></div>
          <div v-if="updateInfo?.update_available" style="margin-top: 8px;">
            <span class="badge badge-detected" style="font-size: 13px;">
              <span class="badge-dot"></span>
              新版本 v{{ updateInfo.latest }} 可用
            </span>
          </div>
          <div v-else-if="updateInfo && !updateInfo.update_available" style="margin-top: 8px; color: var(--green); font-size: 14px;">
            ✅ 当前已是最新版本
          </div>
        </div>
        <div style="display: flex; gap: 12px;">
          <button class="btn btn-secondary" @click="checkUpdate" :disabled="checkingUpdate">
            {{ checkingUpdate ? '检查中...' : '检查更新' }}
          </button>
          <button class="btn btn-secondary" @click="loadChangelog">更新日志</button>
          <button v-if="updateInfo?.update_available" class="btn btn-primary" @click="doUpdate" :disabled="updating">
            {{ updating ? '更新中...' : '立即更新' }}
          </button>
        </div>
      </div>

      <!-- 更新结果提示 -->
      <div v-if="updateResult" :style="{
        marginTop: '16px', padding: '14px 16px', borderRadius: '12px',
        background: updateSuccess ? 'rgba(52,199,89,0.08)' : 'rgba(255,59,48,0.08)',
        border: '1px solid ' + (updateSuccess ? 'rgba(52,199,89,0.2)' : 'rgba(255,59,48,0.2)'),
        display: 'flex', alignItems: 'center', gap: '10px'
      }">
        <span style="font-size: 18px;">{{ updateSuccess ? '✅' : '❌' }}</span>
        <span style="font-size: 14px;">{{ updateResult }}</span>
      </div>

      <!-- 更新说明 -->
      <div v-if="updateInfo?.update_available && !updateSuccess" class="release-notes-card">
        <div style="font-weight: 600; margin-bottom: 10px;">v{{ updateInfo.latest }} 更新内容</div>
        <div class="release-notes-body" style="white-space: pre-wrap;">{{ updateInfo.release_notes || '暂无更新说明' }}</div>
        <a v-if="updateInfo.release_url && updateInfo.release_url.startsWith('https://')" :href="updateInfo.release_url" target="_blank" style="display: inline-block; margin-top: 10px; font-size: 13px; color: var(--accent);">在 GitHub 查看 →</a>
      </div>
    </div>

    <!-- Changelog Modal -->
    <div v-if="showChangelog" class="modal-overlay" @click.self="showChangelog = false">
      <div class="modal" style="max-width: 600px;">
        <div class="modal-header">更新日志</div>
        <div class="modal-body" style="max-height: 60vh; overflow-y: auto;">
          <div v-if="changelog.length === 0" style="text-align: center; padding: 20px; color: var(--text-secondary);">暂无更新日志</div>
          <div v-for="(entry, i) in changelog" :key="i" class="changelog-entry">
            <div class="changelog-header">
              <span class="changelog-version">{{ entry.name }}</span>
              <span class="changelog-date">{{ formatDate(entry.published_at) }}</span>
            </div>
            <div class="changelog-notes" style="white-space: pre-wrap;">{{ entry.notes || '暂无说明' }}</div>
            <a v-if="entry.url && entry.url.startsWith('https://')" :href="entry.url" target="_blank" class="changelog-link">在 GitHub 查看 →</a>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showChangelog = false">关闭</button>
        </div>
      </div>
    </div>

    <!-- Notification Section -->
    <div v-if="tab === 'notify'" style="display: flex; justify-content: space-between; align-items: center; margin: 28px 0 16px;">
      <h2 style="font-size: 20px; font-weight: 600;">通知设置</h2>
      <div style="display: flex; gap: 12px;">
        <button class="btn btn-secondary" @click="testNotifications" :disabled="testing">
          {{ testing ? '发送中...' : '测试通知' }}
        </button>
        <button class="btn btn-primary" @click="openAdd()">+ 添加通知</button>
      </div>
    </div>

    <div class="card" v-if="tab === 'notify'" id="notify">
      <div v-if="loading" style="text-align: center; padding: 40px;">
        <div class="spinner" style="margin: 0 auto;"></div>
      </div>
      <div v-else-if="notifications.length === 0" class="empty-state">
        <p>还没有配置通知</p>
        <div style="display: flex; gap: 12px; justify-content: center; margin-top: 16px;">
          <button class="btn btn-primary" @click="openAdd('telegram')">添加 Telegram</button>
          <button class="btn btn-primary" @click="openAdd('wecom')">添加企业微信</button>
        </div>
      </div>
      <div v-else class="table-container">
        <table>
          <thead>
            <tr><th>类型</th><th>状态</th><th>通知级别</th><th>配置</th><th style="text-align: right;">操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="n in notifications" :key="n.id">
              <td style="font-weight: 600;">{{ n.type === 'telegram' ? '📱 Telegram' : '💬 企业微信' }}</td>
              <td><span :class="['badge', n.enabled ? 'badge-online' : 'badge-offline']">{{ n.enabled ? '已启用' : '已禁用' }}</span></td>
              <td>{{ levelLabel(n.notify_level) }}</td>
              <td style="font-size: 13px; color: var(--text-secondary); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ n.config }}</td>
              <td style="text-align: right;"><button class="btn btn-sm btn-secondary" @click="openEdit(n)">编辑</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Notification Modal -->
    <div v-if="showModal" class="modal-overlay" @click.self="showModal = false">
      <div class="modal">
        <div class="modal-header">{{ editItem ? '编辑通知' : '添加通知' }}</div>
        <div class="modal-body">
          <!-- Type selector for new notifications -->
          <div v-if="!editItem" class="form-group">
            <label class="form-label">通知类型</label>
            <div style="display: flex; gap: 12px;">
              <button :class="['btn', notifyType === 'telegram' ? 'btn-primary' : 'btn-secondary']" @click="notifyType = 'telegram'">📱 Telegram</button>
              <button :class="['btn', notifyType === 'wecom' ? 'btn-primary' : 'btn-secondary']" @click="notifyType = 'wecom'">💬 企业微信</button>
            </div>
          </div>

          <!-- Telegram fields -->
          <template v-if="notifyType === 'telegram'">
            <div class="form-group">
              <label class="form-label">Telegram Bot Token</label>
              <input class="form-input" v-model="tgForm.bot_token" placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11" />
            </div>
            <div class="form-group">
              <label class="form-label">Chat ID</label>
              <input class="form-input" v-model="tgForm.chat_id" placeholder="123456789" />
            </div>
          </template>

          <!-- WeCom fields -->
          <template v-if="notifyType === 'wecom'">
            <div class="form-group">
              <label class="form-label">企业微信 Webhook URL</label>
              <input class="form-input" v-model="wcForm.webhook" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." />
            </div>
          </template>

          <div class="form-group">
            <label class="form-label">通知级别</label>
            <select class="form-input" v-model="notifyLevel">
              <option value="all">全部通知</option>
              <option value="detected_only">仅新发现</option>
              <option value="detected_and_cleaned">新发现 + 已清除</option>
              <option value="detected_and_confirmed">新发现 + 持续发现</option>
            </select>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showModal = false">取消</button>
          <button class="btn btn-primary" @click="saveNotification">保存</button>
        </div>
      </div>
    </div>

    <!-- Change Password Modal -->
    <div v-if="showPasswordModal" class="modal-overlay" @click.self="showPasswordModal = false">
      <div class="modal">
        <div class="modal-header">修改密码</div>
        <div class="modal-body">
          <div class="form-group">
            <label class="form-label">当前密码</label>
            <input class="form-input" type="password" v-model="passwordForm.old_password" placeholder="请输入当前密码" />
          </div>
          <div class="form-group">
            <label class="form-label">新密码</label>
            <input class="form-input" type="password" v-model="passwordForm.new_password" placeholder="至少8位" />
          </div>
          <div class="form-group">
            <label class="form-label">确认新密码</label>
            <input class="form-input" type="password" v-model="passwordForm.confirm_password" placeholder="再次输入新密码" />
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" @click="showPasswordModal = false">取消</button>
          <button class="btn btn-primary" @click="doChangePassword" :disabled="passwordLoading">
            {{ passwordLoading ? '修改中...' : '确认修改' }}
          </button>
        </div>
      </div>
    </div>

    <!-- TOTP Modal -->
    <div v-if="showTotpModal" class="modal-overlay" @click.self="showTotpModal = false">
      <div class="modal">
        <div class="modal-header">TOTP 身份验证器</div>
        <div class="modal-body">
          <!-- Step 1: Password confirmation -->
          <template v-if="totpStep === 1">
            <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 16px;">请输入密码以验证身份</p>
            <div class="form-group">
              <label class="form-label">密码</label>
              <input class="form-input" type="password" v-model="totpPassword" placeholder="请输入登录密码" @keyup.enter="doResetTotpStep1" />
            </div>
            <div style="display: flex; gap: 12px; justify-content: flex-end;">
              <button class="btn btn-danger" @click="doDisableTotp" :disabled="totpLoading">禁用 TOTP</button>
              <button class="btn btn-primary" @click="doResetTotpStep1" :disabled="totpLoading">
                {{ totpLoading ? '验证中...' : '重新绑定' }}
              </button>
            </div>
          </template>

          <!-- Step 2: Show new TOTP secret -->
          <template v-if="totpStep === 2">
            <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 16px;">请使用身份验证器 App 扫描二维码</p>
            <div style="text-align: center; margin: 16px 0;">
              <div style="background: white; display: inline-block; padding: 16px; border-radius: 12px;">
                <img v-if="totpQrDataUrl" :src="totpQrDataUrl" alt="TOTP QR Code" width="200" height="200" />
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">密钥（手动输入）</label>
              <input class="form-input" :value="totpSecret" readonly style="font-family: monospace; text-align: center;" />
            </div>
            <button class="btn btn-primary" style="width: 100%;" @click="totpStep = 3">已绑定，下一步</button>
          </template>

          <!-- Step 3: Verify code -->
          <template v-if="totpStep === 3">
            <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 16px;">请输入验证器中显示的6位验证码</p>
            <div class="form-group">
              <input class="form-input" v-model="totpCode" placeholder="000000" maxlength="6"
                style="text-align: center; font-size: 24px; letter-spacing: 8px; font-family: monospace;"
                @keyup.enter="doResetTotpStep3" />
            </div>
            <button class="btn btn-primary" style="width: 100%;" @click="doResetTotpStep3" :disabled="totpLoading">
              {{ totpLoading ? '验证中...' : '验证并完成' }}
            </button>
          </template>
        </div>
        <div class="modal-footer" v-if="totpStep === 1">
          <button class="btn btn-secondary" @click="showTotpModal = false">取消</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.changelog-entry { padding: 16px 0; border-bottom: 1px solid var(--border); }
.changelog-entry:last-child { border-bottom: none; }
.changelog-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.changelog-version { font-size: 16px; font-weight: 600; }
.changelog-date { font-size: 13px; color: var(--text-secondary); }
.changelog-notes { font-size: 14px; color: var(--text-secondary); max-height: 150px; overflow-y: auto; margin-bottom: 8px; line-height: 1.6; }
.changelog-notes :deep(h2) { font-size: 15px; font-weight: 600; color: var(--text); margin: 12px 0 6px; }
.changelog-notes :deep(h3) { font-size: 14px; font-weight: 600; color: var(--text); margin: 10px 0 4px; }
.changelog-notes :deep(ul) { padding-left: 18px; margin: 4px 0; }
.changelog-notes :deep(li) { margin: 2px 0; }
.changelog-notes :deep(code) { background: rgba(0,0,0,0.06); padding: 1px 5px; border-radius: 4px; font-size: 13px; }
.changelog-notes :deep(a) { color: var(--accent); }

.release-notes-card { margin-top: 16px; padding: 16px; background: rgba(0,122,255,0.04); border: 1px solid rgba(0,122,255,0.1); border-radius: 12px; }
.release-notes-body { font-size: 14px; color: var(--text-secondary); max-height: 200px; overflow-y: auto; line-height: 1.6; }
.release-notes-body :deep(h2) { font-size: 15px; font-weight: 600; color: var(--text); margin: 12px 0 6px; }
.release-notes-body :deep(h3) { font-size: 14px; font-weight: 600; color: var(--text); margin: 10px 0 4px; }
.release-notes-body :deep(ul) { padding-left: 18px; margin: 4px 0; }
.release-notes-body :deep(li) { margin: 2px 0; }
.release-notes-body :deep(code) { background: rgba(0,0,0,0.06); padding: 1px 5px; border-radius: 4px; font-size: 13px; }
.release-notes-body :deep(a) { color: var(--accent); }
.changelog-link { font-size: 13px; color: var(--accent); text-decoration: none; }
.changelog-link:hover { text-decoration: underline; }

.settings-grid { display: flex; flex-direction: column; gap: 8px; }
.settings-item {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px 16px;
  border-radius: 12px;
  cursor: pointer;
  transition: background 0.15s;
  border: 1px solid var(--border);
}
.settings-item:hover { background: rgba(0,0,0,0.03); }
.settings-item-icon {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.settings-item-title { font-size: 14px; font-weight: 600; }
.settings-item-desc { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }
</style>
