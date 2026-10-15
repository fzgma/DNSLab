#!/usr/bin/env bash
set -euo pipefail

dnslab_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$dnslab_root"
dnslab_build="$dnslab_root/build"
mkdir -p "$dnslab_build"

dnslab_gcc_prefix=/opt/rh/gcc-toolset-15/root/usr
export PATH="$dnslab_gcc_prefix/bin:$PATH"
export LD_LIBRARY_PATH="$dnslab_gcc_prefix/lib64:$dnslab_gcc_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CC="$dnslab_gcc_prefix/bin/gcc"
export CXX="$dnslab_gcc_prefix/bin/g++"
export AR="$dnslab_gcc_prefix/bin/ar"
export RANLIB="$dnslab_gcc_prefix/bin/ranlib"
# 清除镜像继承的架构参数及共享 C++ 运行库选项。
unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
for dnslab_compiler in "$CC" "$CXX"; do
    dnslab_version=$("$dnslab_compiler" -dumpfullversion -dumpversion)
    if [[ "${dnslab_version%%.*}" != 15 ]]; then
        echo "需要 GCC 15：$dnslab_compiler 当前版本为 $dnslab_version" >&2
        exit 1
    fi
    "$dnslab_compiler" --version
done
for dnslab_library in libstdc++.a libgcc.a; do
    dnslab_library_path=$("$CXX" -print-file-name="$dnslab_library")
    case "$dnslab_library_path" in
        "$dnslab_gcc_prefix/"*) test -f "$dnslab_library_path" ;;
        *) echo "缺少 GCC 15 静态运行库：$dnslab_library_path" >&2; exit 1 ;;
    esac
done

dnslab_baseline=$(python -c '
import json, re
with open("vcpkg.json", encoding="utf-8") as manifest:
    baseline = json.load(manifest)["builtin-baseline"]
if not re.fullmatch(r"[0-9a-f]{40}", baseline):
    raise SystemExit("vcpkg.json 的 builtin-baseline 必须填写完整提交编号")
print(baseline)
')
export VCPKG_ROOT="$dnslab_root/build-deps/vcpkg"
export VCPKG_BINARY_SOURCES=clear
export VCPKG_DISABLE_METRICS=1
export VCPKG_FORCE_SYSTEM_BINARIES=1
export VCPKG_MAX_CONCURRENCY=2
if [[ ! -d "$VCPKG_ROOT/.git" ]]; then
    git clone --filter=blob:none --no-checkout https://github.com/microsoft/vcpkg.git "$VCPKG_ROOT"
fi
git -C "$VCPKG_ROOT" checkout --detach "$dnslab_baseline"
test "$(git -C "$VCPKG_ROOT" rev-parse HEAD)" = "$dnslab_baseline"
bash "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
"$VCPKG_ROOT/vcpkg" version

cmake --fresh -S "$dnslab_root" -B "$dnslab_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
    "-DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    "-DVCPKG_OVERLAY_TRIPLETS=$dnslab_root/.github/scripts/triplets" \
    -DVCPKG_TARGET_TRIPLET=x64-linux-generic \
    -DVCPKG_HOST_TRIPLET=x64-linux-generic \
    "-DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=$dnslab_root/.github/scripts/toolchains/gcc15.cmake"
cmake --build "$dnslab_build" --parallel 2

# 只打包运行测试所需的产物，避免携带依赖安装目录和完整构建目录。
dnslab_programs=(dnslab dnslab_tests dnslab_integration_tests)
for dnslab_program in "${dnslab_programs[@]}"; do
    test -x "$dnslab_build/$dnslab_program"
    dnslab_dynamic=$(readelf -d "$dnslab_build/$dnslab_program")
    if [[ "$dnslab_dynamic" == *libstdc++.so* || "$dnslab_dynamic" == *libgcc_s.so* ]]; then
        echo "$dnslab_program 意外依赖了共享 C++ 运行库" >&2
        exit 1
    fi
    ldd "$dnslab_build/$dnslab_program"
done
test -f "$dnslab_build/dnslab-test-metadata.cmake"
test -f "$dnslab_build/test-support/Catch.cmake"
test -f "$dnslab_build/test-support/CatchAddTests.cmake"
(
    cd "$dnslab_build"
    sha256sum "${dnslab_programs[@]}" dnslab-test-metadata.cmake test-support/* > SHA256SUMS
    tar -czf dnslab-linux-x86_64.tar.gz \
        "${dnslab_programs[@]}" dnslab-test-metadata.cmake test-support SHA256SUMS
    sha256sum dnslab-linux-x86_64.tar.gz
)
