#!/bin/bash
# PVE-Advanced-Tools 卸载脚本

set -euo pipefail

SERVICE_NAME="pve-advanced-tools"
INSTALL_DIR="/opt/pve-advanced-tools"

echo "=== PVE-Advanced-Tools 卸载脚本 ==="

# 检查是否 root
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ 请使用 root 运行此脚本"
    exit 1
fi

# 停止服务
echo "1. 停止服务..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true

# 禁用开机自启
echo "2. 禁用开机自启..."
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

# 删除 systemd 服务
echo "3. 删除服务文件..."
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload

# 删除安装目录
echo "4. 删除安装目录..."
read -p "是否删除数据目录 $INSTALL_DIR？(y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$INSTALL_DIR"
    echo "   ✅ 已删除"
else
    echo "   ⏭ 保留数据目录"
fi

echo ""
echo "=== 卸载完成 ==="
