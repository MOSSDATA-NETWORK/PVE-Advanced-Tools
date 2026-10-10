import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

export const hostsApi = {
  list: () => api.get('/hosts').then(r => r.data),
  get: (id: number) => api.get(`/hosts/${id}`).then(r => r.data),
  create: (data: any) => api.post('/hosts', data).then(r => r.data),
  update: (id: number, data: any) => api.put(`/hosts/${id}`, data).then(r => r.data),
  delete: (id: number) => api.delete(`/hosts/${id}`).then(r => r.data),
  test: (id: number) => api.post(`/hosts/${id}/test`).then(r => r.data),
  components: (id: number) => api.get(`/hosts/${id}/components`).then(r => r.data),
  deploy: (id: number) => api.post(`/hosts/${id}/deploy`).then(r => r.data),
}

export const scansApi = {
  list: (limit = 20, offset = 0) => api.get('/scans', { params: { limit, offset } }).then(r => r.data),
  get: (id: number) => api.get(`/scans/${id}`).then(r => r.data),
  create: (hostId?: number) => api.post('/scans', { host_id: hostId }).then(r => r.data),
  stop: (id: number) => api.post(`/scans/${id}/stop`).then(r => r.data),
}

export const resultsApi = {
  list: (params?: { host_id?: number; status?: string; limit?: number; offset?: number }) =>
    api.get('/results', { params }).then(r => r.data),
  stats: () => api.get('/results/stats').then(r => r.data),
}

export const notificationsApi = {
  list: () => api.get('/notifications').then(r => r.data),
  create: (data: any) => api.post('/notifications', data).then(r => r.data),
  update: (id: number, data: any) => api.put(`/notifications/${id}`, data).then(r => r.data),
  test: () => api.post('/notifications/test').then(r => r.data),
}

export const versionApi = {
  current: () => api.get('/version').then(r => r.data),
  check: () => api.get('/version/check').then(r => r.data),
  changelog: () => api.get('/version/changelog').then(r => r.data),
  update: () => api.post('/version/update').then(r => r.data),
}

export const jobsApi = {
  list: (params?: { host_id?: number; status?: string; limit?: number; offset?: number }) =>
    api.get('/jobs', { params }).then(r => r.data),
  get: (id: number) => api.get(`/jobs/${id}`).then(r => r.data),
  create: (hostId: number, spec: any) => api.post(`/hosts/${hostId}/jobs`, spec).then(r => r.data),
  retry: (id: number) => api.post(`/jobs/${id}/retry`).then(r => r.data),
}

export const auditApi = {
  list: (params?: { limit?: number; offset?: number; action?: string; actor?: string }) =>
    api.get('/audit', { params }).then(r => r.data),
}

export const vmsApi = {
  list: (hostId: number) => api.get(`/hosts/${hostId}/vms`).then(r => r.data),
  sync: (hostId: number) => api.post(`/hosts/${hostId}/vms/sync`).then(r => r.data),
  events: (hostId: number) => api.get(`/hosts/${hostId}/vm-events`).then(r => r.data),
}

export const hostkeyApi = {
  scan: (hostId: number) => api.post(`/hosts/${hostId}/hostkey/scan`).then(r => r.data),
  confirm: (hostId: number, fingerprint: string) => api.post(`/hosts/${hostId}/hostkey/confirm`, { fingerprint }).then(r => r.data),
  probe: (hostId: number) => api.post(`/hosts/${hostId}/probe`).then(r => r.data),
}

export const authApi = {
  changePassword: (data: { old_password: string; new_password: string }) => api.post('/auth/password', data).then(r => r.data),
  resetTotp: (password: string) => api.post('/auth/reset-totp', { password }).then(r => r.data),
  disableTotp: (password: string) => api.post('/auth/disable-totp', { password }).then(r => r.data),
}

export const passkeyApi = {
  hasPasskey: (username?: string) => api.post('/passkey/has', username ? { username } : {}).then(r => r.data),
  loginStart: (username?: string) => api.post('/passkey/login/start', username ? { username } : {}).then(r => r.data),
  loginFinish: (username: string, credential: any) => api.post('/passkey/login/finish', { username: username || undefined, credential }).then(r => r.data),
  registerStart: () => api.post('/passkey/register/start').then(r => r.data),
  registerFinish: (credential: any) => api.post('/passkey/register/finish', credential).then(r => r.data),
  delete: () => api.post('/passkey/delete').then(r => r.data),
}

export const netguardApi = {
  listPorts: () => api.get('/netguard/ports').then(r => r.data),
  addPort: (data: any) => api.post('/netguard/ports', data).then(r => r.data),
  delPort: (id: number) => api.delete(`/netguard/ports/${id}`).then(r => r.data),
  togglePort: (id: number) => api.post(`/netguard/ports/${id}/toggle`).then(r => r.data),
  listDomains: () => api.get('/netguard/domains').then(r => r.data),
  addDomain: (data: any) => api.post('/netguard/domains', data).then(r => r.data),
  importDomains: (text: string) => api.post('/netguard/domains/import', { text }).then(r => r.data),
  delDomain: (id: number) => api.delete(`/netguard/domains/${id}`).then(r => r.data),
  toggleDomain: (id: number) => api.post(`/netguard/domains/${id}/toggle`).then(r => r.data),
  getScope: () => api.get('/netguard/scope').then(r => r.data),
  setScope: (host_id: number, enabled: boolean) => api.post('/netguard/scope', { host_id, enabled }).then(r => r.data),
  addWhitelist: (data: any) => api.post('/netguard/whitelist', data).then(r => r.data),
  delWhitelist: (id: number) => api.delete(`/netguard/whitelist/${id}`).then(r => r.data),
  deploy: () => api.post('/netguard/deploy').then(r => r.data),
  logs: (hostId: number) => api.post(`/netguard/logs/${hostId}`).then(r => r.data),
  getLogEnabled: () => api.get('/netguard/log-enabled').then(r => r.data),
  setLogEnabled: (enabled: boolean) => api.post('/netguard/log-enabled', { enabled }).then(r => r.data),
}

export const arpApi = {
  modes: () => api.get('/arp/modes').then(r => r.data),
  setMode: (hostId: number, mode: string) => api.post(`/arp/mode/${hostId}`, { mode }).then(r => r.data),
  uninstall: (hostId: number) => api.post(`/arp/uninstall/${hostId}`).then(r => r.data),
  sync: (hostId: number) => api.post(`/arp/sync/${hostId}`).then(r => r.data),
  whitelistList: (hostId: number) => api.get(`/arp/whitelist/${hostId}/list`).then(r => r.data),
  whitelistAdd: (host_id: number, vmid: number) => api.post('/arp/whitelist', { host_id, vmid }).then(r => r.data),
  whitelistDel: (id: number) => api.delete(`/arp/whitelist/${id}`).then(r => r.data),
  mapList: (hostId: number) => api.get(`/arp/maps/${hostId}/list`).then(r => r.data),
  mapAdd: (data: any) => api.post('/arp/maps', data).then(r => r.data),
  mapImport: (host_id: number, text: string) => api.post('/arp/maps/import', { host_id, text }).then(r => r.data),
  mapDel: (id: number) => api.delete(`/arp/maps/${id}`).then(r => r.data),
}

export const qosApi = {
  templates: () => api.get('/qos/templates').then(r => r.data),
  createTemplate: (data: any) => api.post('/qos/templates', data).then(r => r.data),
  delTemplate: (id: number) => api.delete(`/qos/templates/${id}`).then(r => r.data),
  assignTemplate: (hostId: number, template_id: number | null) => api.post(`/qos/template/${hostId}`, { template_id }).then(r => r.data),
  policies: (hostId?: number) => api.get('/qos/policies', { params: hostId ? { host_id: hostId } : {} }).then(r => r.data),
  savePolicy: (data: any) => api.post('/qos/policies', data).then(r => r.data),
  delPolicy: (id: number) => api.delete(`/qos/policies/${id}`).then(r => r.data),
  togglePolicy: (id: number) => api.post(`/qos/policies/${id}/toggle`).then(r => r.data),
  events: (params: any) => api.get('/qos/events', { params }).then(r => r.data),
  nodes: () => api.get('/qos/nodes').then(r => r.data),
  issueToken: (hostId: number, purpose: string) => api.post(`/qos/hosts/${hostId}/token`, { purpose }).then(r => r.data),
  tokens: (hostId: number) => api.get(`/qos/hosts/${hostId}/tokens`).then(r => r.data),
  clusters: () => api.get('/qos/clusters').then(r => r.data),
  install: (hostId: number) => api.post(`/qos/install/${hostId}`).then(r => r.data),
  configApply: (hostId: number) => api.post(`/qos/config/${hostId}`).then(r => r.data),
  uninstall: (hostId: number) => api.post(`/qos/uninstall/${hostId}`).then(r => r.data),
  status: (hostId: number) => api.post(`/qos/status/${hostId}`).then(r => r.data),
}

export const dashboardApi = {
  overview: () => api.get('/dashboard').then(r => r.data),
}

export const optimizeApi = {
  init: (hostId: number) => api.post(`/optimize/init/${hostId}`).then(r => r.data),
  tune: (hostId: number) => api.post(`/optimize/tune/${hostId}`).then(r => r.data),
  rollback: (hostId: number, component: string) => api.post(`/optimize/rollback/${hostId}`, { component }).then(r => r.data),
}

export const signaturesApi = {
  list: () => api.get('/signatures').then(r => r.data),
  create: (data: any) => api.post('/signatures', data).then(r => r.data),
  toggle: (id: number) => api.post(`/signatures/${id}/toggle`).then(r => r.data),
  del: (id: number) => api.delete(`/signatures/${id}`).then(r => r.data),
  push: (hostId: number) => api.post(`/signatures/push/${hostId}`).then(r => r.data),
}

export const arpStatsApi = {
  list: (hostId: number) => api.get(`/arp/stats/${hostId}`).then(r => r.data),
  collect: (hostId: number) => api.post(`/arp/stats/${hostId}`).then(r => r.data),
}

export const settingsApi = {
  get: () => api.get('/settings').then(r => r.data),
  put: (key: string, value: string) => api.put('/settings', { key, value }).then(r => r.data),
}
