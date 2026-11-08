<script setup lang="ts">
import { ref } from 'vue'
import axios from 'axios'
import { passkeyApi } from '../api'
import { registerPasskey, passkeyUnavailableReason } from '../passkey'
import { generateQrDataUrl } from '../qr'

const props = defineProps<{ password: string }>()
const emit = defineEmits<{ done: [method: 'totp' | 'passkey'] }>()

const view = ref<'choose' | 'totp'>('choose')
const secret = ref('')
const qrDataUrl = ref('')
const code = ref('')
const busy = ref(false)
const error = ref('')
const copied = ref(false)
const passkeyReason = passkeyUnavailableReason()

let copiedTimer: ReturnType<typeof setTimeout> | undefined

function onCodeInput(e: Event) {
  const el = e.target as HTMLInputElement
  const digits = el.value.replace(/\D/g, '').slice(0, 6)
  code.value = digits
  el.value = digits
}

function selectSecret() {
  const el = document.getElementById('mfa-secret')
  if (!el) return
  const range = document.createRange()
  range.selectNodeContents(el)
  const selection = window.getSelection()
  selection?.removeAllRanges()
  selection?.addRange(range)
}

async function copySecret() {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(secret.value)
      copied.value = true
      clearTimeout(copiedTimer)
      copiedTimer = setTimeout(() => { copied.value = false }, 2000)
      return
    } catch {
      selectSecret()
      return
    }
  }
  selectSecret()
}

async function startTotp() {
  busy.value = true
  error.value = ''
  try {
    const res = await axios.post('/api/auth/totp/setup', { password: props.password })
    if (!res.data.ok) {
      error.value = res.data.error
      return
    }
    const qr = await generateQrDataUrl(res.data.totp_uri)
    secret.value = res.data.totp_secret
    qrDataUrl.value = qr
    copied.value = false
    code.value = ''
    view.value = 'totp'
  } catch (e: any) {
    error.value = e.response?.data?.error || e.message
  } finally {
    busy.value = false
  }
}

async function startPasskey() {
  busy.value = true
  error.value = ''
  try {
    const startRes = await passkeyApi.registerStart()
    if (!startRes.ok) {
      error.value = startRes.error
      return
    }
    const credential = await registerPasskey({
      challenge: startRes.challenge,
      rp: startRes.rp,
      user: startRes.user,
      excludeCredentials: startRes.excludeCredentials,
    })
    const finishRes = await passkeyApi.registerFinish(credential)
    if (finishRes.ok) {
      emit('done', 'passkey')
    } else {
      error.value = finishRes.error
    }
  } catch (e: any) {
    if (e.name === 'NotAllowedError') {
      error.value = '已取消或超时，请重试'
    } else {
      error.value = e.response?.data?.error || e.message
    }
  } finally {
    busy.value = false
  }
}

async function confirmTotp() {
  if (busy.value || code.value.length !== 6) return
  busy.value = true
  error.value = ''
  try {
    const res = await axios.post('/api/auth/totp/confirm', { code: code.value })
    if (res.data.ok) {
      emit('done', 'totp')
    } else {
      error.value = res.data.error
    }
  } catch (e: any) {
    error.value = e.response?.data?.error || e.message
  } finally {
    busy.value = false
  }
}

function back() {
  view.value = 'choose'
  code.value = ''
  error.value = ''
}
</script>

<template>
  <div>
    <template v-if="view === 'choose'">
      <h2>绑定二次验证</h2>
      <p class="lead">选择一种方式。之后登录需要：用户名 + 密码 + TOTP 验证码，或直接使用 Passkey。</p>
      <p v-if="error" class="mfa-error" role="alert">{{ error }}</p>
      <div class="options">
        <button type="button" class="option" :disabled="busy" @click="startTotp">
          <span class="option-title">身份验证器 App（TOTP）</span>
          <span class="option-desc">用 Google Authenticator、Microsoft Authenticator、1Password 等扫码，登录时输入 6 位验证码</span>
        </button>
        <button
          type="button"
          class="option"
          :disabled="busy || passkeyReason !== ''"
          :aria-describedby="passkeyReason ? 'passkey-unavailable' : undefined"
          @click="startPasskey"
        >
          <span class="option-title">Passkey</span>
          <span class="option-desc" :id="passkeyReason ? 'passkey-unavailable' : undefined">{{ passkeyReason || '用指纹、面容或安全密钥直接登录，无需输入密码' }}</span>
        </button>
      </div>
    </template>

    <template v-else>
      <h2>扫描二维码</h2>
      <p class="lead">用身份验证器 App 扫描下方二维码，或手动输入密钥</p>
      <div class="qr-wrap">
        <div class="qr-box">
          <img :src="qrDataUrl" alt="TOTP 绑定二维码" width="200" height="200" />
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">密钥（手动输入）</label>
        <div class="secret-row">
          <p id="mfa-secret" class="secret">{{ secret }}</p>
          <button type="button" class="btn btn-sm copy-btn" :disabled="busy" @click="copySecret">{{ copied ? '已复制' : '复制' }}</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label" for="mfa-code">验证码</label>
        <input
          id="mfa-code"
          class="form-input"
          :value="code"
          inputmode="numeric"
          autocomplete="one-time-code"
          placeholder="6 位数字"
          @input="onCodeInput"
          @keyup.enter="confirmTotp"
        />
      </div>
      <p v-if="error" class="mfa-error" role="alert">{{ error }}</p>
      <div class="actions">
        <button type="button" class="btn btn-primary" :disabled="busy || code.length !== 6" @click="confirmTotp">
          {{ busy ? '处理中...' : '验证并完成' }}
        </button>
        <button type="button" class="btn btn-secondary" :disabled="busy" @click="back">返回</button>
      </div>
    </template>
  </div>
</template>

<style scoped>
h2 {
  margin: 0 0 8px;
  font-size: 20px;
  font-weight: 700;
  text-align: center;
  color: var(--text);
}
.lead {
  margin: 0 0 20px;
  font-size: 14px;
  line-height: 1.5;
  color: var(--text-secondary);
}
.mfa-error {
  color: var(--red);
  font-size: 14px;
  margin: 0 0 12px;
}
.options {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.option {
  display: block;
  width: 100%;
  background: var(--bg-secondary);
  border: 1px solid rgba(0, 0, 0, 0.12);
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  min-height: 64px;
  text-align: left;
  cursor: pointer;
  transition: border-color 0.2s;
  font-family: inherit;
  color: inherit;
}
.option:hover:not(:disabled),
.option:focus-visible {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.15);
}
.option:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.option-title {
  display: block;
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
}
.option-desc {
  display: block;
  margin-top: 2px;
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.5;
}
.qr-wrap {
  display: flex;
  justify-content: center;
  margin-bottom: 16px;
}
.qr-box {
  background: white;
  border-radius: var(--radius-sm);
  padding: 12px;
  line-height: 0;
}
.secret-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
}
.secret {
  flex: 1;
  min-width: 0;
  margin: 0;
  color: var(--text);
  font-family: monospace;
  font-size: 14px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.copy-btn:focus-visible,
.actions .btn:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
.actions {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.actions .btn {
  width: 100%;
  min-height: 44px;
}
.actions .btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
