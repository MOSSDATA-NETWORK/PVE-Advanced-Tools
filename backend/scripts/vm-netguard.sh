#!/bin/bash
# vm-netguard — PVE 母机 VM 出网管控（平台版，由 PVE-Advanced-Tools 下发）
#
# 与上游脚本的区别：
#   1) 配置外置：从 /etc/vm-netguard.conf 读取（BLOCK_DOMAINS / DROP_PORTS / WHITELIST_VMIDS）
#   2) 支持 VM 白名单：名单内 VM 的 tap 口流量在封堵规则之前 RETURN（豁免）
#   3) uninstall 不再把 bridge-nf 内核开关改回 0（PVE 官方默认值就是 1，贸然改回会破坏其他依赖）
#   4) 新增 status 命令：输出规则命中计数（供平台回采拦截统计）
#
# 用法:
#   vm-netguard.sh apply      应用当前配置（幂等：先清自家规则再按配置重建）
#   vm-netguard.sh install    装入 /usr/local/sbin + systemd 开机自启 + 立即应用
#   vm-netguard.sh uninstall  删自家规则、停服务、删文件
#   vm-netguard.sh status     输出 JSON 状态（规则数、命中计数）
#
# 原理与验证方法见 PVE-shell/vm-netguard/README.md

set -u

SCRIPT_NAME="vm-netguard"
INSTALL_PATH="/usr/local/sbin/${SCRIPT_NAME}.sh"
UNIT_PATH="/etc/systemd/system/${SCRIPT_NAME}.service"
CONF_FILE="/etc/vm-netguard.conf"
SYSCTL_CONF="/etc/sysctl.d/99-${SCRIPT_NAME}.conf"
CHAIN4="VMNETGUARD"
CHAIN6="VMNETGUARD6"

# 默认配置（无配置文件时的兜底；平台下发总是先写配置再 apply）
BLOCK_DOMAINS=""
DROP_PORTS=""
ENABLE_LOG="0"  # 1 = 拦截前写内核日志（前缀 NG_PORT:/NG_DOMAIN:，限速 5/min）
WHITELIST_VMIDS=""
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

# 域名转 DNS 线上格式的十六进制匹配模式
str2hex() {
  local s="$1" out="" i c
  for ((i = 0; i < ${#s}; i++)); do
    printf -v c '%02x' "'${s:i:1}"
    out+="$c"
  done
  printf '%s' "$out"
}

domain_to_hex() {
  local label pat="" hex
  IFS='.' read -ra _labels <<< "$1"
  for label in "${_labels[@]}"; do
    printf -v hex '%02x' "${#label}"
    pat+="$hex$(str2hex "$label")"
  done
  printf '|%s00|' "$pat"
}

# 清理指定链及其在 FORWARD 的全部跳转引用（循环删，防重复引用残留）
purge_chain() {
  local bin="$1" chain="$2"
  while "$bin" -D FORWARD -j "$chain" 2>/dev/null; do :; done
  "$bin" -F "$chain" 2>/dev/null || true
  "$bin" -X "$chain" 2>/dev/null || true
}

# 清理本组件自建链（含历史残留的 _TMP/_OLD）
flush_own() {
  purge_chain iptables "$CHAIN4"
  purge_chain ip6tables "$CHAIN6"
  purge_chain iptables "${CHAIN4}_TMP"
  purge_chain ip6tables "${CHAIN6}_TMP"
  purge_chain iptables "${CHAIN4}_OLD"
  purge_chain ip6tables "${CHAIN6}_OLD"
}

# 向指定链写入全部规则（显式错误传播：任一失败返回非零，调用方保留旧链）
build_chain() {
  local bin="$1" chain="$2"
  "$bin" -N "$chain" 2>/dev/null || "$bin" -F "$chain" || return 1

  # 白名单 VM 豁免（tap<vmid>i+ 匹配该 VM 全部网卡，guest 无法伪造）
  local vmid
  for vmid in $WHITELIST_VMIDS; do
    "$bin" -A "$chain" -i "tap${vmid}i+" -j RETURN || return 1
  done

  # 禁 VM 对外 SMTP / BT（静默 DROP；ENABLE_LOG=1 时先记日志）
  if [ -n "$DROP_PORTS" ]; then
    if [ "$ENABLE_LOG" = "1" ]; then
      "$bin" -A "$chain" -p tcp -m multiport --dports "$DROP_PORTS" -m limit --limit 5/min -j LOG --log-prefix "NG_PORT: " --log-level 6 || return 1
    fi
    "$bin" -A "$chain" -p tcp -m multiport --dports "$DROP_PORTS" -j DROP || return 1
  fi

  # 按域名拦截：SNI(443) / HTTP(80) / QUIC(UDP 443) / DNS(53)
  local d hex rej
  for d in $BLOCK_DOMAINS; do
    hex=$(domain_to_hex "$d")
    if [ "$bin" = "iptables" ]; then rej="icmp-port-unreachable"; else rej="icmp6-port-unreachable"; fi
    if [ "$ENABLE_LOG" = "1" ]; then
      # iptables log-prefix 上限 29 字符："NG_DOMAIN(" + 域名 + "): "，域名最多 16 字符，超出截断
      local dshort="${d:0:16}"
      "$bin" -A "$chain" -p tcp --dport 443 -m string --string "$d" --algo bm -m limit --limit 5/min -j LOG --log-prefix "NG_DOMAIN($dshort): " --log-level 6 || return 1
    fi
    "$bin" -A "$chain" -p tcp --dport 443 -m string --string "$d" --algo bm -j REJECT --reject-with tcp-reset || return 1
    "$bin" -A "$chain" -p tcp --dport 80 -m string --string "$d" --algo bm -j REJECT --reject-with tcp-reset || return 1
    "$bin" -A "$chain" -p udp --dport 443 -m string --string "$d" --algo bm -j REJECT --reject-with "$rej" || return 1
    "$bin" -A "$chain" -p udp --dport 53 -m string --hex-string "$hex" --algo bm -j REJECT --reject-with "$rej" || return 1
    "$bin" -A "$chain" -p tcp --dport 53 -m string --hex-string "$hex" --algo bm -j REJECT --reject-with tcp-reset || return 1
  done
}

# 单栈切换：挂临时链、摘除旧链引用（旧链内容保留，供失败回挂）
swap_attach() {
  local bin="$1" tmp="$2" live="$3"
  "$bin" -I FORWARD 1 -j "$tmp" || return 1
  while "$bin" -D FORWARD -j "$live" 2>/dev/null; do :; done
}

# 双栈都切换成功后：旧链改名 <name>_OLD 保留内容（可回滚），临时链转正
swap_commit() {
  local bin="$1" tmp="$2" live="$3" old="${3}_OLD"
  if "$bin" -S "$live" >/dev/null 2>&1; then
    purge_chain "$bin" "$old"          # 清掉上次 apply 的残留
    "$bin" -E "$live" "$old" || return 1
  fi
  "$bin" -E "$tmp" "$live"
}

# commit 全部成功后删除旧链
swap_cleanup() {
  purge_chain iptables "${CHAIN4}_OLD"
  purge_chain ip6tables "${CHAIN6}_OLD"
}

# 失败恢复：优先从 _OLD 链完整恢复；首次安装（无旧链）则拆除已转正的新链；
# attach 阶段失败时把未挂载的旧链挂回（-C 防重复引用）
swap_rollback() {
  local bin chain tmp old had
  for spec in "iptables:$CHAIN4:$HAD_CHAIN4" "ip6tables:$CHAIN6:$HAD_CHAIN6"; do
    bin="${spec%%:*}"; rest="${spec#*:}"
    chain="${rest%%:*}"; had="${rest##*:}"
    tmp="${chain}_TMP"; old="${chain}_OLD"
    purge_chain "$bin" "$tmp"
    if "$bin" -S "$old" >/dev/null 2>&1; then
      # commit 阶段失败且有旧链：摘掉新链、旧链回名并挂载
      purge_chain "$bin" "$chain"
      "$bin" -E "$old" "$chain"
      "$bin" -C FORWARD -j "$chain" 2>/dev/null || "$bin" -I FORWARD 1 -j "$chain"
    elif [ "$had" = "0" ]; then
      # 首次安装失败：转正的新链整体拆除，回到无规则状态
      purge_chain "$bin" "$chain"
    elif "$bin" -S "$chain" >/dev/null 2>&1 && ! "$bin" -C FORWARD -j "$chain" 2>/dev/null; then
      # attach 阶段失败：旧链内容还在，挂回即可
      "$bin" -I FORWARD 1 -j "$chain" 2>/dev/null || true
    fi
  done
}

apply_rules() {
  # 桥接流量过 netfilter（PVE 官方默认值为 1）
  modprobe br_netfilter 2>/dev/null || true
  sysctl -w net.bridge.bridge-nf-call-iptables=1  >/dev/null || { echo "sysctl 写入失败"; exit 1; }
  sysctl -w net.bridge.bridge-nf-call-arptables=1 >/dev/null || { echo "sysctl 写入失败"; exit 1; }
  sysctl -w net.bridge.bridge-nf-call-ip6tables=1 >/dev/null || { echo "sysctl 写入失败"; exit 1; }
  cat > "$SYSCTL_CONF" <<'EOF'
# vm-netguard 依赖：桥接 VM 流量过 netfilter（PVE 官方默认值）
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-arptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

  # 记录切换前旧链是否存在（首次安装不存在，失败恢复时新链应整体拆除）
  HAD_CHAIN4=0; HAD_CHAIN6=0
  iptables  -S "$CHAIN4" >/dev/null 2>&1 && HAD_CHAIN4=1
  ip6tables -S "$CHAIN6" >/dev/null 2>&1 && HAD_CHAIN6=1

  # 显式逐段检查（不用 `if ! ( set -e )`：条件上下文会抑制 errexit，形同虚设）
  build_chain iptables  "${CHAIN4}_TMP" || { echo "$SCRIPT_NAME: IPv4 规则构建失败，未动现有规则"; purge_chain iptables "${CHAIN4}_TMP"; exit 1; }
  build_chain ip6tables "${CHAIN6}_TMP" || { echo "$SCRIPT_NAME: IPv6 规则构建失败，未动现有规则"; purge_chain iptables "${CHAIN4}_TMP"; purge_chain ip6tables "${CHAIN6}_TMP"; exit 1; }

  swap_attach iptables  "${CHAIN4}_TMP" "$CHAIN4" || { echo "$SCRIPT_NAME: IPv4 切换失败，恢复原规则"; swap_rollback; exit 1; }
  swap_attach ip6tables "${CHAIN6}_TMP" "$CHAIN6" || { echo "$SCRIPT_NAME: IPv6 切换失败，恢复原规则"; swap_rollback; exit 1; }
  swap_commit iptables  "${CHAIN4}_TMP" "$CHAIN4" || { echo "$SCRIPT_NAME: IPv4 提交失败，恢复原规则"; swap_rollback; exit 1; }
  swap_commit ip6tables "${CHAIN6}_TMP" "$CHAIN6" || { echo "$SCRIPT_NAME: IPv6 提交失败，恢复原规则"; swap_rollback; exit 1; }
  swap_cleanup

  echo "$SCRIPT_NAME: 规则已应用（拦截域名: ${BLOCK_DOMAINS:-无} / 禁端口: ${DROP_PORTS:-无} / 白名单: ${WHITELIST_VMIDS:-无}）"
}

do_install() {
  install -m 0755 "$0" "$INSTALL_PATH"
  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=VM outbound guard (platform-managed): port drop + domain block (SNI/DNS)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_PATH apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$SCRIPT_NAME" >/dev/null 2>&1
  echo "$SCRIPT_NAME: 已安装（$INSTALL_PATH + $UNIT_PATH，开机自动应用）"
}

do_uninstall() {
  systemctl disable --now "$SCRIPT_NAME" 2>/dev/null
  flush_own
  rm -f "$UNIT_PATH" "$INSTALL_PATH" "$SYSCTL_CONF" "$CONF_FILE"
  systemctl daemon-reload 2>/dev/null
  # 注意：不还原 bridge-nf 内核开关（1 是 PVE 官方默认值，改回 0 会破坏 PVE 防火墙等功能）
  echo "$SCRIPT_NAME: 已卸载（bridge-nf 开关保持 PVE 默认值 1）"
}

do_status() {
  local rules4 rules6 hits4 hits6
  rules4=$(iptables  -S "$CHAIN4" 2>/dev/null | grep -c '^-A' || true)
  rules6=$(ip6tables -S "$CHAIN6" 2>/dev/null | grep -c '^-A' || true)
  hits4=$(iptables  -nvL "$CHAIN4" 2>/dev/null | awk 'NR>2 {s+=$1} END {print s+0}')
  hits6=$(ip6tables -nvL "$CHAIN6" 2>/dev/null | awk 'NR>2 {s+=$1} END {print s+0}')
  local svc="inactive"
  systemctl is-active "$SCRIPT_NAME" >/dev/null 2>&1 && svc="active"
  printf '{"service":"%s","rules_v4":%s,"rules_v6":%s,"hits_v4":%s,"hits_v6":%s,"domains":"%s","ports":"%s","whitelist":"%s"}\n' \
    "$svc" "${rules4:-0}" "${rules6:-0}" "${hits4:-0}" "${hits6:-0}" "$BLOCK_DOMAINS" "$DROP_PORTS" "$WHITELIST_VMIDS"
}

# 最近拦截日志（内核日志中的 NG_* 记录，需 ENABLE_LOG=1 后 apply 过才产生）
do_logs() {
  journalctl -k --since '-2 hours' --no-pager 2>/dev/null | grep -E 'NG_PORT:|NG_DOMAIN' | tail -100 && return 0
  dmesg 2>/dev/null | grep -E 'NG_PORT:|NG_DOMAIN' | tail -100
}

case "${1:-apply}" in
  apply) apply_rules ;;
  install) do_install; apply_rules ;;
  uninstall) do_uninstall ;;
  status) do_status ;;
  logs) do_logs ;;
  *) echo "用法: $0 [apply|install|uninstall|status|logs]"; exit 1 ;;
esac
