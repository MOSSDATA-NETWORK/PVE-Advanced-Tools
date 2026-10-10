#!/bin/bash
# chicken-check.sh — PVE 切鸡检测脚本 (v4)
# 用法:
#   chicken-check.sh --all                  批量扫描（并行，GA模式进VM检查，无GA标记needs_disk）
#   chicken-check.sh --vmid <id>            单台扫描（GA优先，无GA则磁盘挂载）
#   chicken-check.sh --vmid <id> --disk     强制磁盘挂载模式
#   chicken-check.sh --check-agent          检测脚本是否已安装
#
# 检测原理：
#   GA模式  : qm guest exec 进入VM检查 文件/systemd/bash_history/网络（1-3秒/台）
#   磁盘模式: 复制磁盘→qemu-nbd只读挂载→检查文件系统（10-60秒/台，仅单台）
# 检测特征：/opt/incus, incushlii-agent, NodeHatch痕迹(项目/证书/zabbly源/8443), incus/lxd服务, history关键词
# 注意：nodeget-agent 是开源监控 NodeGet(github.com/NodeSeekDev/NodeGet) 的正常组件，不属于切鸡特征
# 输出：JSON

set -uo pipefail

SELF="$0"
MODE="all"
TARGET_VMID=""
VM_STATUS=""
FORCE_DISK=false
ONELINE=false
PARALLEL="${CHICKEN_PARALLEL:-20}"
GA_TIMEOUT=8
MOUNT_POINT="/tmp/chicken-mount-$$"

while [[ $# -gt 0 ]]; do
    case $1 in
        --vmid) TARGET_VMID="$2"; MODE="single"; shift 2 ;;
        --vmstatus) VM_STATUS="$2"; shift 2 ;;
        --all) MODE="all"; shift ;;
        --disk) FORCE_DISK=true; shift ;;
        --oneline) ONELINE=true; shift ;;
        --check-agent) echo '{"ok":true,"agent":"installed"}'; exit 0 ;;
        --version) echo "6"; exit 0 ;;
        *) shift ;;
    esac
done

# ---- VM 内检测逻辑（base64 编码后经 qm guest exec 传入，避免引号地狱）----
CHECK_B64=$(cat <<'CHECKEOF' | base64 | tr -d '\n'
found=""
[ -d /opt/incus ] && found="${found}incus_dir "
[ -e /usr/local/bin/incushlii-agent ] && found="${found}incushlii_agent "
[ -d /var/lib/incus ] && found="${found}incus_data "
# LXD 需有运营痕迹才计: 已init(lxd.db/database)或有容器/存储池
# (Debian 12 apt装lxd未init时也有/var/lib/lxd目录, 纯目录不算切鸡)
lxd_used=""
[ -f /var/lib/lxd/lxd.db ] && lxd_used=1
[ -d /var/lib/lxd/database ] && lxd_used=1
ls /var/lib/lxd/containers 2>/dev/null | grep -q . && lxd_used=1
ls /var/lib/lxd/disks 2>/dev/null | grep -q . && lxd_used=1
[ -n "$lxd_used" ] && found="${found}lxd "
# NodeHatch（基于Incus的VPS分割面板）专属痕迹
nh_proj=$( (incus project list 2>/dev/null || /opt/incus/bin/incus project list 2>/dev/null) | grep -ci nodehatch || true)
[ "${nh_proj:-0}" -gt 0 ] && found="${found}nodehatch_proj "
nh_cert=$( (incus config trust list 2>/dev/null || /opt/incus/bin/incus config trust list 2>/dev/null) | grep -ci nodehatch || true)
[ "${nh_cert:-0}" -gt 0 ] && found="${found}nodehatch_cert "
[ -f /etc/apt/sources.list.d/zabbly-incus-stable.sources ] && found="${found}zabbly_incus "
# 注意：/usr/local/bin/nodeget-agent 是开源监控 NodeGet（github.com/NodeSeekDev/NodeGet）的
# 正常组件，不是切鸡特征，不检测
svc=$(ls /etc/systemd/system/ 2>/dev/null | grep -ciE "incus|shlii|nodehatch" || true)
det=""
# 明细段(##key=item1|item2)：随数量一起上报具体命中的服务名/命令/连接，供平台详情展示
# 清洗: 去掉引号/反斜杠/#/|(会破坏提取与分段), 历史命令截断100字符
[ "${svc:-0}" -gt 0 ] && found="${found}svc:${svc} " \
  && det="##svc=$(ls /etc/systemd/system/ 2>/dev/null | grep -iE "incus|shlii|nodehatch" | sed 's/["\\#|,]/ /g' | tr '\n' ',' | sed 's/,$//')"
for h in /root/.bash_history /home/*/.bash_history; do
  [ -f "$h" ] || continue
  hc=$(grep -ciE "shlii\.io|incushlii|nodehatch|docs\.nodehatch\.com" "$h" 2>/dev/null || true)
  [ "${hc:-0}" -gt 0 ] && found="${found}hist:${hc} " \
    && det="${det}##hist=$(grep -ihE "shlii\.io|incushlii|nodehatch|docs\.nodehatch\.com" "$h" 2>/dev/null | sed 's/["\\#|,]/ /g' | cut -c1-100 | tr '\n' ',' | sed 's/,$//')"
done
# 网络连接是瞬态的：一次采样，计数与明细同源，避免两次ss之间连接断开导致计数有明细无
net_lines=$(ss -tnp 2>/dev/null | grep -iE "incushlii|shlii|nodehatch")
net=$(echo "$net_lines" | grep -c .)
[ "${net:-0}" -gt 0 ] && found="${found}net:${net} " \
  && det="${det}##net=$(echo "$net_lines" | sed 's/["\\#|,]/ /g' | cut -c1-100 | tr '\n' ',' | sed 's/,$//')"
# 8443 只有在 incusd 进程监听时才算特征（其他软件也常用8443，避免误报）
l8443=$(ss -tlnp 2>/dev/null | grep ':8443' | grep -ci incusd || true)
[ "${l8443:-0}" -gt 0 ] && found="${found}api_8443 "
[ -n "$found" ] && echo "FOUND:${found}${det}" || echo "CLEAN"
CHECKEOF
)

# 从 qm guest exec 的 JSON 输出中提取 out-data 内容
extract_out() {
    # 输入: {"exitcode":0,"exited":1,"out-data":"CLEAN\n",...}
    grep -o '"out-data"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | sed 's/.*:[[:space:]]*"//; s/"$//; s/\\n//g'
}

# GA 模式检测：进入 VM 内部
check_vm_ga() {
    local vmid="$1"
    local out
    out=$(timeout "$GA_TIMEOUT" qm guest exec "$vmid" -- bash -c "echo $CHECK_B64 | base64 -d | bash" 2>/dev/null | extract_out)
    if echo "$out" | grep -q "FOUND:"; then
        local ev
        ev=$(echo "$out" | sed 's/.*FOUND://; s/[[:space:]]*$//')
        echo "detected|ga|$ev"
    elif echo "$out" | grep -q "CLEAN"; then
        echo "clean|ga|"
    else
        # GA在线但exec被禁用/超时（如管理员策略）→ 归为待检测，走磁盘扫描
        echo "needs_disk_scan|ga|ga_exec_disabled"
    fi
}

# 磁盘挂载检测：复制磁盘→qemu-nbd只读挂载→检查文件系统
check_vm_disk() {
    local vmid="$1"
    # 查找磁盘路径（支持 local-lvm 和 dir 存储）
    local disk_line disk_path
    disk_line=$(qm config "$vmid" 2>/dev/null | grep -E '^(scsi0|virtio0|sata0|ide0):' | head -1)
    if [ -z "$disk_line" ]; then
        echo "error|disk|no_disk_config"; return
    fi
    local disk_vol
    disk_vol=$(echo "$disk_line" | sed 's/^[^:]*: *//; s/,.*//')

    local nbd_dev="/dev/nbd1"
    modprobe nbd max_part=8 2>/dev/null || true
    qemu-nbd --disconnect "$nbd_dev" >/dev/null 2>&1 || true
    sleep 1

    # 解析实际磁盘文件路径
    local real_path
    real_path=$(pvesm path "$disk_vol" 2>/dev/null)
    if [ -z "$real_path" ]; then
        echo "error|disk|path_not_found"; return
    fi

    # LVM 块设备直接连，qcow2/raw 文件也可连
    if ! qemu-nbd --read-only --connect="$nbd_dev" "$real_path" 2>/dev/null; then
        echo "error|disk|nbd_failed"; return
    fi
    sleep 2

    mkdir -p "$MOUNT_POINT"
    local mounted=0 part
    # 按文件系统类型选挂载参数：ext 系列用 noload，XFS 用 norecovery（noload 会报错）
    for part in nbd1p2 nbd1p5 nbd1p3 nbd1p1 nbd1; do
        local fstype
        fstype=$(blkid -s TYPE -o value "/dev/$part" 2>/dev/null)
        [ -z "$fstype" ] && continue
        local mopts="ro"
        case "$fstype" in
            ext2|ext3|ext4) mopts="ro,noload" ;;
            xfs)            mopts="ro,norecovery" ;;
            btrfs)          mopts="ro" ;;
        esac
        if mount -o "$mopts" "/dev/$part" "$MOUNT_POINT" 2>/dev/null; then
            mounted=1; break
        fi
        # 兜底：纯只读再试一次
        if mount -o ro "/dev/$part" "$MOUNT_POINT" 2>/dev/null; then
            mounted=1; break
        fi
    done

    local result="error|disk|mount_failed"
    if [ $mounted -eq 1 ]; then
        local found=""
        [ -d "$MOUNT_POINT/opt/incus" ] && found="${found}incus_dir "
        [ -e "$MOUNT_POINT/usr/local/bin/incushlii-agent" ] && found="${found}incushlii_agent "
        [ -d "$MOUNT_POINT/var/lib/incus" ] && found="${found}incus_data "
        # LXD 需有运营痕迹才计: 已init或有容器/存储池(纯目录是Debian闲置包, 不算)
        lxd_used=""
        [ -f "$MOUNT_POINT/var/lib/lxd/lxd.db" ] && lxd_used=1
        [ -d "$MOUNT_POINT/var/lib/lxd/database" ] && lxd_used=1
        ls "$MOUNT_POINT/var/lib/lxd/containers" 2>/dev/null | grep -q . && lxd_used=1
        ls "$MOUNT_POINT/var/lib/lxd/disks" 2>/dev/null | grep -q . && lxd_used=1
        [ -n "$lxd_used" ] && found="${found}lxd "
        # NodeHatch 痕迹（zabbly 源是它 install.sh 写入的 Incus 软件源）
        [ -f "$MOUNT_POINT/etc/apt/sources.list.d/zabbly-incus-stable.sources" ] && found="${found}zabbly_incus "
        # nodeget-agent 是开源监控 NodeGet 的正常组件，不是切鸡特征，不检测
        local svc
        svc=$(ls "$MOUNT_POINT/etc/systemd/system/" 2>/dev/null | grep -ciE "incus|shlii|nodehatch" || true)
        local det=""
        [ "${svc:-0}" -gt 0 ] && found="${found}svc:${svc} " \
          && det="##svc=$(ls "$MOUNT_POINT/etc/systemd/system/" 2>/dev/null | grep -iE "incus|shlii|nodehatch" | sed 's/["\\#|,]/ /g' | tr '\n' ',' | sed 's/,$//')"
        local hc
        hc=$(grep -ciE "shlii\.io|incushlii|nodehatch|docs\.nodehatch\.com" "$MOUNT_POINT/root/.bash_history" 2>/dev/null || true)
        [ "${hc:-0}" -gt 0 ] && found="${found}hist:${hc} " \
          && det="${det}##hist=$(grep -ihE "shlii\.io|incushlii|nodehatch|docs\.nodehatch\.com" "$MOUNT_POINT/root/.bash_history" 2>/dev/null | sed 's/["\\#|,]/ /g' | cut -c1-100 | tr '\n' ',' | sed 's/,$//')"
        umount "$MOUNT_POINT" 2>/dev/null
        if [ -n "$found" ]; then
            result="detected|disk|${found% }${det}"
        else
            result="clean|disk|"
        fi
    fi

    qemu-nbd --disconnect "$nbd_dev" >/dev/null 2>&1 || true
    rmdir "$MOUNT_POINT" 2>/dev/null || true
    echo "$result"
}

# 检测单个 VM 并输出一行 JSON
# 注意：批量模式通过 xargs 带 --vmid 自调用，此时 MODE=="single"，
# 不能用 MODE 区分批量/单台 —— 批量调用的标志是显式传了 --vmstatus
detect_and_output() {
    local vmid="$1" vmstatus="$2"
    local batch=false
    [ -n "$vmstatus" ] && batch=true

    # 批量模式：stopped VM 跳过（磁盘扫描太慢，需手动触发）
    if $batch && [ "$vmstatus" != "running" ]; then
        echo "{\"vmid\":\"$vmid\",\"method\":\"none\",\"status\":\"skipped\",\"evidence\":\"vm_stopped\"}"
        return
    fi

    local r
    if [ "$FORCE_DISK" = true ]; then
        r=$(check_vm_disk "$vmid")
    elif timeout 3 qm guest cmd "$vmid" ping &>/dev/null; then
        r=$(check_vm_ga "$vmid")
    elif $batch; then
        # 批量模式无GA → 标记待磁盘扫描（不阻塞批量）
        r="needs_disk_scan|none|no_guest_agent"
    else
        # 单台模式无GA → 磁盘挂载
        r=$(check_vm_disk "$vmid")
    fi

    local st m ev
    st=$(echo "$r" | cut -d'|' -f1)
    m=$(echo "$r" | cut -d'|' -f2)
    ev=$(echo "$r" | cut -d'|' -f3)
    echo "{\"vmid\":\"$vmid\",\"method\":\"$m\",\"status\":\"$st\",\"evidence\":\"$ev\"}"
}

# ---- oneline 模式（供 xargs 并行调用）----
if [ "$ONELINE" = true ]; then
    detect_and_output "$TARGET_VMID" "$VM_STATUS"
    exit 0
fi

# ---- 单台模式 ----
if [ "$MODE" = "single" ] && [ -n "$TARGET_VMID" ]; then
    echo '{"results":['
    # 第三参数留空 = 非批量（无GA时走磁盘挂载完整检测）
    detect_and_output "$TARGET_VMID" ""
    echo ']}'
    exit 0
fi

# ---- 批量模式：xargs 并行自调用 ----
# 进度文件：每处理完一个 VM 写入 "已处理数 已发现数"，供平台后端轮询实现实时进度
PROGRESS_FILE="${CHICKEN_PROGRESS:-}"
[ -n "$PROGRESS_FILE" ] && : > "$PROGRESS_FILE" 2>/dev/null

echo '{"results":['
sep=""
n=0; found=0
qm list 2>/dev/null | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1"|"$(NF-3)}' \
    | xargs -P "$PARALLEL" -I LINE bash -c 'v="${1%%|*}"; s="${1##*|}"; exec "'"$SELF"'" --oneline --vmid "$v" --vmstatus "$s"' _ LINE \
    | while IFS= read -r line; do
        [ -z "$line" ] && continue
        n=$((n+1))
        case "$line" in *'"detected"'*) found=$((found+1));; esac
        printf '%s%s' "$sep" "$line"
        sep=","
        [ -n "$PROGRESS_FILE" ] && echo "$n $found" > "$PROGRESS_FILE" 2>/dev/null
      done
echo
echo ']}'
