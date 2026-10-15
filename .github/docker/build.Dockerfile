# syntax=docker/dockerfile:1
ARG BASE_IMAGE=quay.io/pypa/manylinux_2_28_x86_64
FROM ${BASE_IMAGE}

# 持续集成每次拉取并重新构建镜像，不导出依赖缓存。
RUN dnf install -y gcc-toolset-15-gcc gcc-toolset-15-gcc-c++ \
        gcc-toolset-15-libstdc++-devel gcc-toolset-15-binutils \
        git curl zip unzip tar gzip make perl-core pkgconf-pkg-config ca-certificates \
    && dnf clean all
ENV PATH="/opt/python/cp312-cp312/bin:${PATH}"
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
        cmake==3.31.6 ninja==1.11.1.3

WORKDIR /workspace
