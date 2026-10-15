#!/usr/bin/env bash
set -euo pipefail

# Only runtime test tools: this image never builds DNSLab or its dependencies.
source /etc/os-release
case "$ID" in
    ubuntu|debian)
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            cmake python3 tar gzip coreutils
        rm -rf /var/lib/apt/lists/*
        ;;
    arch)
        pacman -Syu --noconfirm --needed cmake python tar gzip coreutils
        pacman -Scc --noconfirm
        ;;
    *)
        echo "Unsupported runtime distribution: $ID" >&2
        exit 1
        ;;
esac
cmake --version
