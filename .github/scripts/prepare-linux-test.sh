#!/usr/bin/env bash
set -euo pipefail

# 仅安装运行测试所需的工具，镜像不编译 DNSLab 或其依赖。
source /etc/os-release
case "$ID" in
    ubuntu|debian)
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            cmake python3 tar gzip coreutils ca-certificates
        rm -rf /var/lib/apt/lists/*
        ;;
    arch)
        pacman -Syu --noconfirm --needed cmake python tar gzip coreutils ca-certificates
        pacman -Scc --noconfirm
        ;;
    *)
        echo "不支持此运行环境发行版：$ID" >&2
        exit 1
        ;;
esac
cmake --version
