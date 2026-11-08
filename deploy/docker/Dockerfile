# PVE-Advanced-Tools 运行镜像（Debian 12）。发布时由 CI 构建，并作为文件附在 GitHub Release 上。
# 自行构建：把 Linux x86_64 发布版程序放到仓库根目录，命名为 pve-advanced-tools-linux-x86_64，然后
#   docker build -f deploy/docker/Dockerfile -t pve-advanced-tools .
FROM debian:12-slim

# ssh/scp/ssh-keyscan/ssh-keygen 连接母机，sshpass 用于密码认证，ca-certificates 用于检查更新与通知
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 pvetools \
 && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin pvetools \
 && install -d -m 700 -o 10001 -g 10001 /data

COPY --chmod=755 pve-advanced-tools-linux-x86_64 /usr/local/bin/pve-advanced-tools
COPY --chmod=755 deploy/docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# DEPLOY_MODE=docker：面板内「立即更新」改为提示拉取新镜像（容器内替换程序会在重建容器时丢失）
ENV HOST=0.0.0.0 \
    PORT=3210 \
    DATABASE_URL=sqlite:/data/pve-advanced-tools.db?mode=rwc \
    DATA_DIR=/data \
    DEPLOY_MODE=docker

USER 10001:10001
WORKDIR /data
VOLUME /data
EXPOSE 3210
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
