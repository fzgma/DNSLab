# syntax=docker/dockerfile:1
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

COPY .github/scripts/prepare-linux-test.sh /opt/dnslab/prepare-linux-test.sh
RUN bash /opt/dnslab/prepare-linux-test.sh

WORKDIR /workspace
