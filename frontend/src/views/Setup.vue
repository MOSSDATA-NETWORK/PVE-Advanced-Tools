<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import { passkeyApi } from '../api'
import { registerPasskey, isWebAuthnSupported } from '../passkey'

const router = useRouter()
const step = ref(1) // 1=创建账户, 2=Passkey注册, 3=完成
const username = ref('')
const password = ref('')
const confirmPassword = ref('')
const loading = ref(false)
const error = ref('')
const passkeySupported = ref(false)
const passkeyRegistered = ref(false)
const passkeyLoading = ref(false)

onMounted(async () => {
  try {
    const res = await axios.get('/api/auth/check')
    if (res.data.initialized) {
      router.push('/login')
    }
  } catch {}

  passkeySupported.value = isWebAuthnSupported()
})

async function doSetup() {
  const name = username.value.trim()
  if (name.length < 2 || name.length > 32) {
    error.value = '用户名长度需在2-32位'
    return
  }
  if (password.value.length < 8) {
    error.value = '密码至少8位'
    return
  }
  if (password.value !== confirmPassword.value) {
    error.value = '两次密码不一致'
    return
  }

  loading.value = true
  error.value = ''
  try {
    const res = await axios.post('/api/auth/setup', {
      username: username.value,
      password: password.value,
      enable_totp: false,
    })
    if (res.data.ok) {
      if (passkeySupported.value) {
        step.value = 2
      } else {
        step.value = 3
      }
    } else {
      error.value = res.data.error
    }
  } catch (e: any) {
    error.value = e.response?.data?.error || '设置失败'
  } finally {
    loading.value = false
  }
}

async function doRegisterPasskey() {
  passkeyLoading.value = true
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
      passkeyRegistered.value = true
      step.value = 3
    } else {
      error.value = finishRes.error || 'Passkey 注册失败'
    }
  } catch (e: any) {
    if (e.name === 'NotAllowedError') {
      error.value = '用户取消了 Passkey 注册'
    } else {
      error.value = e.message || 'Passkey 注册失败'
    }
  } finally {
    passkeyLoading.value = false
  }
}

function skipPasskey() {
  step.value = 3
}

function finish() {
  router.push('/')
}
</script>

<template>
  <div class="setup-page">
    <div class="setup-card">
      <!-- Step 1: 创建账户 -->
      <template v-if="step === 1">
        <div class="setup-logo">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="40" height="40">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
        </div>
        <h1 class="setup-title">初始化设置</h1>
        <p class="setup-subtitle">首次运行，请设置管理员账户</p>

        <div class="form-group">
          <label class="form-label">用户名</label>
          <input class="form-input" v-model="username" placeholder="请输入用户名" />
        </div>
        <div class="form-group">
          <label class="form-label">密码</label>
          <input class="form-input" type="password" v-model="password" placeholder="至少8位" />
        </div>
        <div class="form-group">
          <label class="form-label">确认密码</label>
          <input class="form-input" type="password" v-model="confirmPassword" placeholder="再次输入密码" @keyup.enter="doSetup" />
        </div>

        <div v-if="error" style="color: var(--red); font-size: 14px; margin-bottom: 16px;">{{ error }}</div>

        <button class="btn btn-primary" style="width: 100%;" @click="doSetup" :disabled="loading">
          {{ loading ? '创建中...' : '创建账户' }}
        </button>
      </template>

      <!-- Step 2: Passkey 注册 -->
      <template v-if="step === 2">
        <div style="text-align: center; margin-bottom: 20px;">
          <div style="font-size: 48px; margin-bottom: 12px;">🔑</div>
          <h1 class="setup-title">设置 Passkey</h1>
          <p class="setup-subtitle">使用指纹、面容或安全密钥快速登录，无需输入密码</p>
        </div>

        <div v-if="error" style="color: var(--red); font-size: 14px; margin-bottom: 16px;">{{ error }}</div>

        <button class="btn btn-primary" style="width: 100%; margin-bottom: 12px;" @click="doRegisterPasskey" :disabled="passkeyLoading">
          {{ passkeyLoading ? '注册中...' : '注册 Passkey' }}
        </button>

        <button class="btn btn-secondary" style="width: 100%;" @click="skipPasskey">
          跳过，稍后设置
        </button>
      </template>

      <!-- Step 3: 完成 -->
      <template v-if="step === 3">
        <div style="text-align: center;">
          <div style="font-size: 48px; margin-bottom: 16px;">✅</div>
          <h1 class="setup-title">设置完成</h1>
          <p class="setup-subtitle">
            {{ passkeyRegistered ? 'Passkey 已注册，可以使用指纹或面容登录' : '管理员账户已创建' }}
          </p>
          <button class="btn btn-primary" style="margin-top: 24px;" @click="finish">
            进入控制台
          </button>
        </div>
      </template>
    </div>
  </div>
</template>

<style scoped>
.setup-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg);
}
.setup-card {
  background: var(--bg-secondary);
  border-radius: 20px;
  box-shadow: var(--shadow-lg);
  padding: 40px;
  width: 100%;
  max-width: 420px;
}
.setup-logo { text-align: center; color: var(--accent); margin-bottom: 16px; }
.setup-title { text-align: center; font-size: 24px; font-weight: 700; margin-bottom: 4px; }
.setup-subtitle { text-align: center; font-size: 14px; color: var(--text-secondary); margin-bottom: 28px; }
</style>
