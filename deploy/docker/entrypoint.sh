#!/bin/sh
# 容器入口：准备加密密钥后启动面板。
# MASTER_KEY 加密保存的母机凭据，丢失或更换后已存凭据无法解密：只在全新的数据目录里生成新密钥。
set -eu
umask 077

data=/data
key_file=$data/master.key

if ! [ -w "$data" ]; then
  echo "错误：$data 不可写。挂载宿主机目录时请先执行 chown 10001:10001 <宿主机目录>" >&2
  exit 1
fi

if [ -z "${MASTER_KEY:-}" ]; then
  if [ -f "$key_file" ]; then
    MASTER_KEY=$(cat "$key_file")
  else
    # 数据库路径按 DATABASE_URL 解析（与 sqlx 相同：去掉 sqlite:// 或 sqlite: 前缀和 ? 之后的参数；相对路径以工作目录 /data 为准）
    url=${DATABASE_URL:-sqlite:pve-advanced-tools.db?mode=rwc}
    db=${url#sqlite://}
    [ "$db" != "$url" ] || db=${url#sqlite:}
    db=${db%%\?*}
    # sqlx 会解码 %xx，这里无法可靠还原：含 % 时无法确认库是否存在，宁可拒绝也不生成新密钥
    case $db in
      *%*)
        echo "错误：DATABASE_URL 中的数据库路径含 % 编码，无法确认数据库是否已存在。请用 MASTER_KEY 环境变量或 $key_file 提供密钥" >&2
        exit 1
        ;;
    esac
    if [ -e "$db" ]; then
      echo "错误：数据库 $db 已存在，但缺少 master.key。请放回原来的 master.key（或用 MASTER_KEY 环境变量提供原密钥）；新密钥无法解密已保存的凭据" >&2
      exit 1
    fi
    MASTER_KEY=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
    printf '%s\n' "$MASTER_KEY" > "$key_file.tmp"
    mv "$key_file.tmp" "$key_file"
    echo "已生成加密密钥：$key_file（请连同数据卷一起备份）" >&2
  fi
fi

case "$MASTER_KEY" in
  *[!0-9a-fA-F]*) bad=1 ;;
  *) bad=0 ;;
esac
if [ "$bad" = 1 ] || [ "${#MASTER_KEY}" -ne 64 ]; then
  echo "错误：MASTER_KEY 必须是 64 位 hex（检查 MASTER_KEY 环境变量或 $key_file）" >&2
  exit 1
fi
export MASTER_KEY

exec /usr/local/bin/pve-advanced-tools "$@"
