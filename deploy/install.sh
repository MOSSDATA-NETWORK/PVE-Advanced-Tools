#!/bin/bash
# PVE-Advanced-Tools 一键部署脚本
# 用法: bash install.sh [端口号]
# 默认端口: 3210

set -euo pipefail

PORT="${1:-3210}"
INSTALL_DIR="/opt/pve-advanced-tools"
SERVICE_NAME="pve-advanced-tools"
BINARY_NAME="pve-advanced-tools"

echo "=== PVE-Advanced-Tools 部署脚本 ==="
echo "安装目录: $INSTALL_DIR"
echo "端口: $PORT"
echo ""

# 检查是否 root
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ 请使用 root 运行此脚本"
    exit 1
fi

# 检查 sshpass（密码认证需要）
if ! command -v sshpass &>/dev/null; then
    echo "⚠️  sshpass 未安装，密码认证方式将不可用"
    echo "   安装: apt install sshpass / yum install sshpass"
fi

# 创建目录
echo "1. 创建安装目录..."
mkdir -p "$INSTALL_DIR"

# 复制文件
echo "2. 复制文件..."
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -f "$SCRIPT_DIR/target/release/pve-advanced-tools-backend" ]; then
    cp "$SCRIPT_DIR/target/release/pve-advanced-tools-backend" "$INSTALL_DIR/$BINARY_NAME"
elif [ -f "$SCRIPT_DIR/backend/target/release/pve-advanced-tools-backend" ]; then
    cp "$SCRIPT_DIR/backend/target/release/pve-advanced-tools-backend" "$INSTALL_DIR/$BINARY_NAME"
elif [ -f "$SCRIPT_DIR/$BINARY_NAME" ]; then
    cp "$SCRIPT_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
else
    echo "❌ 未找到二进制文件"
    echo "   请先构建（backend 目录 cargo build --release）或将 pve-advanced-tools 放在脚本同级目录"
    exit 1
fi
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# 复制静态文件
if [ -d "$SCRIPT_DIR/backend/static" ]; then
    cp -r "$SCRIPT_DIR/backend/static" "$INSTALL_DIR/static"
    echo "   ✅ 前端静态文件已复制"
elif [ -d "$SCRIPT_DIR/static" ]; then
    cp -r "$SCRIPT_DIR/static" "$INSTALL_DIR/static"
    echo "   ✅ 前端静态文件已复制"
else
    echo "⚠️  未找到 static 目录，API 可用但前端页面不可用"
fi

# 复制迁移文件
if [ -d "$SCRIPT_DIR/backend/migrations" ]; then
    cp -r "$SCRIPT_DIR/backend/migrations" "$INSTALL_DIR/migrations"
fi

# 加密密钥：首次安装生成并持久化（root 600），重装复用——丢失/变更将导致已存凭据无法解密
echo "3. 准备加密密钥..."
if [ ! -f "$INSTALL_DIR/env" ]; then
    if command -v openssl &>/dev/null; then
        MASTER_KEY="$(openssl rand -hex 32)"
    else
        MASTER_KEY="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
    printf 'MASTER_KEY=%s\n' "$MASTER_KEY" > "$INSTALL_DIR/env"
    chmod 600 "$INSTALL_DIR/env"
    echo "   ✅ 已生成 MASTER_KEY（$INSTALL_DIR/env）"
else
    echo "   ✅ 复用已有 MASTER_KEY"
fi

# 安装 systemd 服务
echo "4. 安装 systemd 服务..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=PVE-Advanced-Tools — PVE hypervisor management platform
Documentation=https://github.com/MOSSDATA-NETWORK/PVE-Advanced-Tools
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME
Restart=on-failure
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=60
Environment=PORT=$PORT
Environment=STATIC_DIR=$INSTALL_DIR/static
Environment=DATABASE_URL=sqlite:$INSTALL_DIR/pve-advanced-tools.db?mode=rwc
Environment=DATA_DIR=$INSTALL_DIR/data
EnvironmentFile=$INSTALL_DIR/env
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths=$INSTALL_DIR
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pve-advanced-tools

[Install]
WantedBy=multi-user.target
EOF

# 启用并启动
echo "5. 启用开机自启..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo "6. 启动服务..."
systemctl start "$SERVICE_NAME"

# 等待启动
sleep 2

# 检查状态
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ""
    echo "=== 部署完成 ✅ ==="
    echo ""
    echo "访问地址: http://$(hostname -I | awk '{print $1}'):$PORT"
    echo "服务状态: systemctl status $SERVICE_NAME"
    echo "查看日志: journalctl -u $SERVICE_NAME -f"
    echo "重启服务: systemctl restart $SERVICE_NAME"
    echo "停止服务: systemctl stop $SERVICE_NAME"
    echo ""
    echo "首次访问请完成初始化设置（管理员用户名 + 密码）"
else
    echo ""
    echo "❌ 服务启动失败，查看日志："
    echo "   journalctl -u $SERVICE_NAME -n 20"
fi
