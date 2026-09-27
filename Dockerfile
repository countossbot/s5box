# s5box —— 多订阅空间随机负载代理
# 单阶段 + 直接下载 sing-box 官方静态二进制（比源码编译快得多，架构用 TARGETARCH 判定）
# 可用 --build-arg BASE_IMAGE=... 换镜像源（国内直连 Docker Hub 常失败）
ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

ARG SINGBOX_VERSION=1.14.2
ARG TARGETARCH
ARG APP_VERSION=dev
ARG BUILD_DATE=unknown

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    SINGBOX_BIN=/usr/local/bin/sing-box \
    PANEL_PORT=8080 \
    SOCKS_PORT=1080 \
    HTTP_PORT=1081 \
    BIND_ADDR=0.0.0.0

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv tini ca-certificates curl tzdata; \
    rm -rf /var/lib/apt/lists/*

# OCI 元数据：CI 通过 --build-arg 注入版本号与构建时间
LABEL org.opencontainers.image.title="s5box" \
      org.opencontainers.image.description="多订阅空间随机负载代理" \
      org.opencontainers.image.source="https://github.com/countossbot/s5box" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="MIT"

# sing-box 静态二进制（arm64 / amd64）
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) SB_ARCH=amd64 ;; \
      arm64) SB_ARCH=arm64 ;; \
      *) echo "不支持的架构: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}.tar.gz"; \
    curl -fsSL "$url" -o /tmp/sb.tar.gz; \
    tar -xzf /tmp/sb.tar.gz -C /tmp; \
    install -m 0755 "/tmp/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box; \
    rm -rf /tmp/sb.tar.gz "/tmp/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}"; \
    /usr/local/bin/sing-box version

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /app/requirements.txt

COPY app /app/app
RUN mkdir -p /data && python3 -c "import ast,sys; [ast.parse(open(f).read(), f) for f in __import__('glob').glob('/app/app/*.py')]" \
    && echo "语法检查通过"

# /data: SQLite + sing-box 工作目录（挂载卷）
VOLUME ["/data"]
EXPOSE 8080 1080 1081

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PANEL_PORT}/healthz" || exit 1

# tini 做 PID 1：转发信号 + 回收孤儿进程，避免僵尸
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "-m", "app.main"]
