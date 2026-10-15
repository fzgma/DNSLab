#!/usr/bin/env bash
set -euo pipefail

dnslab_distribution=${1:?Usage: test-linux.sh ubuntu|debian|arch}
case "$dnslab_distribution" in
    ubuntu|debian|arch) ;;
    *) echo "Unsupported distribution: $dnslab_distribution" >&2; exit 1 ;;
esac
dnslab_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$dnslab_root"
dnslab_build="$dnslab_root/build"
dnslab_logs="$dnslab_build/ci-logs/$dnslab_distribution"
dnslab_runtime="$dnslab_build/runtime-tests/$dnslab_distribution"
mkdir -p "$dnslab_logs"
cat /etc/os-release
cmake --version

tar -xzf "$dnslab_build/dnslab-linux-x86_64.tar.gz" -C "$dnslab_build"
(
    cd "$dnslab_build"
    sha256sum -c SHA256SUMS
)

# Fail visibly when IPv6 loopback is unavailable; never turn it into a skip.
# Docker uses --network host, so this checks the same namespace as the tests.
dnslab_status=0
if ! python3 - <<'PY' > "$dnslab_logs/ipv6.log" 2>&1
import socket

with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server, \
     socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
    server.settimeout(2)
    client.settimeout(2)
    server.bind(("::1", 0))
    client.bind(("::1", 0))
    payload = b"DNSLab IPv6 loopback"
    destination = server.getsockname()
    if client.sendto(payload, destination) != len(payload):
        raise RuntimeError("Incomplete IPv6 datagram")
    received, sender = server.recvfrom(65535)
    if received != payload or sender[:2] != client.getsockname()[:2]:
        raise RuntimeError("IPv6 payload or source endpoint mismatch")
    print(f"IPv6 loopback passed: {sender} -> {destination}")
PY
then
    dnslab_status=1
fi
cat "$dnslab_logs/ipv6.log"

cmake -S "$dnslab_root/tests/runtime" -B "$dnslab_runtime" \
    -G 'Unix Makefiles' -DCMAKE_MAKE_PROGRAM=/bin/true \
    "-DDNSLAB_BUILD_DIR=$dnslab_build"
for dnslab_label in smoke unit integration; do
    if ! ctest --test-dir "$dnslab_runtime" -L "^$dnslab_label$" \
        --output-on-failure --no-tests=error \
        --output-log "$dnslab_logs/$dnslab_label.log" \
        --output-junit "$dnslab_logs/$dnslab_label.xml"; then
        dnslab_status=1
    fi
done
exit "$dnslab_status"
