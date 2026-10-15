# 优先使用显式指定的 vcpkg，否则使用仓库内按构建文档准备的副本。
if(DEFINED ENV{VCPKG_ROOT} AND NOT "$ENV{VCPKG_ROOT}" STREQUAL "")
    set(dnslab_vcpkg_root "$ENV{VCPKG_ROOT}")
else()
    get_filename_component(dnslab_vcpkg_root
        "${CMAKE_CURRENT_LIST_DIR}/../build-deps/vcpkg" ABSOLUTE)
endif()

set(dnslab_vcpkg_toolchain "${dnslab_vcpkg_root}/scripts/buildsystems/vcpkg.cmake")
if(NOT EXISTS "${dnslab_vcpkg_toolchain}")
    message(FATAL_ERROR
        "未找到 vcpkg 工具链：${dnslab_vcpkg_toolchain}。"
        "请按 docs/build.md 将 vcpkg 准备到 build-deps/vcpkg，或设置环境变量 VCPKG_ROOT。")
endif()
include("${dnslab_vcpkg_toolchain}")
