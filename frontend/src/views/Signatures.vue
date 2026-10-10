<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { signaturesApi, hostsApi } from '../api'

const sigs = ref<any[]>([])
const hosts = ref<any[]>([])
const loading = ref(true)
const notice = ref<{ ok: boolean; text: string } | null>(null)
const pushHost = ref<number | null>(null)
const form = ref({ name: '', sig_type: 'path', value: '' })

const typeLabel: Record<string, string> = {
  path: '文件/目录路径',
  service: 'systemd 服务',
  history: 'history 关键词',
}
const typeHint: Record<string, string> = {
  path: '如 /opt/evil-panel（绝对路径，GA 与磁盘模式都检查）',
  service: '如 shady-agent（GA 模式查进程态，磁盘模式查 unit 文件）',
  history: '如 evil.example.com（bash_history 精确子串匹配）',
}

onMounted(loadAll)

async function loadAll() {
  loading.value = true
  try {
    const [r, h] = await Promise.all([signaturesApi.list(), hostsApi.list()])
    if (r.ok) sigs.value = r.data
    if (h.ok) hosts.value = h.data
  } finally {
    loading.value = false
  }
}

function showNotice(ok: boolean, text: string) {
  notice.value = { ok, text }
  setTimeout(() => { notice.value = null }, 5000)
}

async function create() {
  if (!form.value.name || !form.value.value) { showNotice(false, '请填写名称与特征值'); return }
  const res = await signaturesApi.create(form.value)
  if (res.ok) { form.value = { name: '', sig_type: 'path', value: '' }; loadAll() }
  showNotice(res.ok, res.ok ? `已添加（${res.note || '下发后生效'}）` : res.error)
}

async function push() {
  if (!pushHost.value) { showNotice(false, '请选择主机'); return }
  const res = await signaturesApi.push(pushHost.value)
  showNotice(res.ok, res.ok ? `下发任务已创建（#${res.job_id}，见任务中心）` : res.error)
}
</script>

<template>
  <div>
    <div class="page-header">
      <h1 class="page-title">特征库管理</h1>
      <p class="page-subtitle">内置特征检测 incus / NodeHatch 类切鸡痕迹；此处维护自定义追加特征，下发后随扫描生效</p>
    </div>

    <div v-if="notice" :class="notice.ok ? 'notice-ok' : 'notice-err'" style="margin-bottom: 12px;">{{ notice.text }}</div>

    <div class="card" style="margin-bottom: 16px;">
      <h3 style="margin: 0 0 12px; font-size: 16px;">新增特征</h3>
      <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px;">
        <input class="form-input" v-model="form.name" placeholder="名称（如 evilpanel）" style="width: 180px;" />
        <select class="form-input" v-model="form.sig_type" style="width: 160px;">
          <option value="path">文件/目录路径</option>
          <option value="service">systemd 服务</option>
          <option value="history">history 关键词</option>
        </select>
        <input class="form-input" v-model="form.value" placeholder="特征值" style="width: 280px;" />
        <button class="btn btn-primary" @click="create">添加</button>
      </div>
      <p style="font-size: 13px; color: var(--text-secondary);">{{ typeHint[form.sig_type] }}</p>
    </div>

    <div class="card" style="margin-bottom: 16px;">
      <h3 style="margin: 0 0 12px; font-size: 16px;">下发特征库</h3>
      <div style="display: flex; gap: 8px;">
        <select class="form-input" v-model="pushHost" style="width: 200px;">
          <option :value="null">选择主机</option>
          <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.name }}</option>
        </select>
        <button class="btn btn-primary" @click="push">下发到主机</button>
      </div>
      <p style="font-size: 13px; color: var(--text-secondary); margin-top: 8px;">
        写入节点 /etc/chicken-signatures.conf；节点下次扫描自动加载（无需重装检测脚本）。
      </p>
    </div>

    <div class="card">
      <h3 style="margin: 0 0 12px; font-size: 16px;">特征列表</h3>
      <table>
        <thead><tr><th>名称</th><th>类型</th><th>特征值</th><th>来源</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="sg in sigs" :key="sg.id">
            <td style="font-weight: 600;">{{ sg.name }}</td>
            <td>{{ typeLabel[sg.sig_type] || sg.sig_type }}</td>
            <td style="font-family: monospace; font-size: 13px;">{{ sg.value }}</td>
            <td>{{ sg.builtin ? '内置' : '自定义' }}</td>
            <td>{{ sg.enabled ? '启用' : '停用' }}</td>
            <td>
              <button class="btn btn-sm btn-secondary" @click="signaturesApi.toggle(sg.id).then(loadAll)">{{ sg.enabled ? '停用' : '启用' }}</button>
              <button v-if="!sg.builtin" class="btn btn-sm btn-secondary" @click="signaturesApi.del(sg.id).then(loadAll)">删除</button>
            </td>
          </tr>
          <tr v-if="!sigs.length"><td colspan="6" style="text-align: center; color: #888;">暂无自定义特征（内置特征在检测脚本中，无需管理）</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.notice-ok { padding: 8px 12px; background: #dcfce7; border-radius: 6px; }
.notice-err { padding: 8px 12px; background: #fee2e2; border-radius: 6px; }
</style>
