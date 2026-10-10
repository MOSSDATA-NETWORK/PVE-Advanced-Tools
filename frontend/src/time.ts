/**
 * 统一时间格式化（UTC+8 北京时间）
 * SQLite 存储的 CURRENT_TIMESTAMP 是 UTC，不带时区后缀
 */

/** 格式化为北京时间 */
export function formatTime(t: string | null | undefined): string {
  if (!t) return '-'
  const d = parseUtcDate(t)
  if (isNaN(d.getTime())) return '-'
  return d.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
}

/** 相对时间（几分钟前） */
export function timeAgo(t: string | null | undefined): string {
  if (!t) return '-'
  const d = parseUtcDate(t)
  const now = new Date()
  const diff = Math.floor((now.getTime() - d.getTime()) / 1000)
  if (diff < 60) return '刚刚'
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`
  return `${Math.floor(diff / 86400)} 天前`
}

/** 解析 UTC 时间字符串（SQLite 的 CURRENT_TIMESTAMP 没有 Z 后缀） */
function parseUtcDate(t: string): Date {
  // 如果已经有 Z 或 +，直接解析
  if (t.endsWith('Z') || t.includes('+')) return new Date(t)
  // SQLite 的格式：2026-09-01 09:00:12，当作 UTC
  return new Date(t + 'Z')
}

/** 日期格式化 */
export function formatDate(t: string | null | undefined): string {
  if (!t) return '-'
  const d = parseUtcDate(t)
  if (isNaN(d.getTime())) return '-'
  return d.toLocaleDateString('zh-CN', { timeZone: 'Asia/Shanghai' })
}
