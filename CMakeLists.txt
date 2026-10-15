cmake_minimum_required(VERSION 3.25)

project(DNSLab VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)
include(CheckCXXSourceCompiles)
include(CMakePushCheckState)

check_cxx_source_compiles([[
    #include <expected>
    #if !defined(__cpp_lib_expected) || __cpp_lib_expected < 202202L
    #error "需要支持 std::expected 的 C++23 标准库。"
    #endif
    // 确认当前标准库能够构造并读取预期值。
    int main() {
        std::expected<int, int> value{42};
        return value.value() == 42 ? 0 : 1;
    }
]] DNSLAB_HAS_STD_EXPECTED)
if(NOT DNSLAB_HAS_STD_EXPECTED)
    message(FATAL_ERROR "DNSLab 需要支持 C++23 std::expected 的编译器与标准库，请升级工具链。")
endif()

set(dnslab_print_probe [[
    #include <print>
    #if !defined(__cpp_lib_print) || __cpp_lib_print < 202207L
    #error "需要支持 std::print 的 C++23 标准库。"
    #endif
    // 确认当前标准库能够编译并链接格式化输出。
    int main() {
        std::print("{}", 42);
        return 0;
    }
]])
check_cxx_source_compiles("${dnslab_print_probe}" DNSLAB_HAS_STD_PRINT)
# 部分 libstdc++ 工具链将终端输出实现放在附加静态库中，按实际链接结果补齐。
if(NOT DNSLAB_HAS_STD_PRINT AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_LIBRARIES stdc++exp)
    check_cxx_source_compiles("${dnslab_print_probe}" DNSLAB_HAS_STD_PRINT_WITH_STDCXXEXP)
    cmake_pop_check_state()
    if(DNSLAB_HAS_STD_PRINT_WITH_STDCXXEXP)
        set(dnslab_print_libraries stdc++exp)
    endif()
endif()
if(NOT DNSLAB_HAS_STD_PRINT AND NOT DNSLAB_HAS_STD_PRINT_WITH_STDCXXEXP)
    message(FATAL_ERROR "DNSLab 需要支持 C++23 std::print 的编译器与标准库，请升级工具链。")
endif()

# 在依赖未配置时给出可直接执行的预设入口。
macro(dnslab_require_package package)
    find_package(${package} ${ARGN} CONFIG QUIET)
    if(NOT ${package}_FOUND)
        message(FATAL_ERROR
            "未找到 ${package} 的 CMake 配置包。请先按 docs/build.md 准备 vcpkg，"
            "再运行 cmake --preset mingw-debug（Windows GCC）、msvc-debug（Windows MSVC）"
            "或 linux-debug（Linux）。已有依赖可设置 CMAKE_PREFIX_PATH。"
            "VS Code 请使用 CMake: Select Configure Preset 选择对应预设，避免复用缺少工具链的旧缓存。")
    endif()
endmacro()

dnslab_require_package(CLI11)
dnslab_require_package(CURL)

add_library(dnslab_core STATIC
    src/dns/byte_utils.cpp
    src/dns/name_codec.cpp
    src/dns/query_encoder.cpp
    src/dns/message_parser.cpp
    src/net/endpoint.cpp
    src/net/socket.cpp
    src/net/deadline.cpp
    src/net/udp.cpp
    src/net/tcp.cpp
    src/net/encrypted_transport.cpp
    src/app/response_validator.cpp
    src/app/query.cpp
    src/app/udp_query.cpp
    src/app/encrypted_query.cpp)
target_include_directories(dnslab_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(dnslab_core PUBLIC cxx_std_23)
target_link_libraries(dnslab_core PUBLIC ${dnslab_print_libraries})
target_link_libraries(dnslab_core PRIVATE CURL::libcurl)
if(WIN32)
    target_link_libraries(dnslab_core PUBLIC ws2_32)
endif()

configure_file(cmake/version.hpp.in generated/dnslab/version.hpp @ONLY)
add_executable(dnslab src/main.cpp src/cli/output.cpp)
target_include_directories(dnslab PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(dnslab PRIVATE dnslab_core CLI11::CLI11)

# 为指定目标启用当前编译器对应的严格警告。
function(dnslab_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    endif()
endfunction()

dnslab_enable_warnings(dnslab_core)
dnslab_enable_warnings(dnslab)

if(BUILD_TESTING)
    dnslab_require_package(Catch2 3)
    find_package(Threads REQUIRED)
    add_executable(dnslab_tests
        tests/main.cpp
        tests/unit/byte_utils_tests.cpp
        tests/unit/dns_header_tests.cpp
        tests/unit/name_codec_tests.cpp
        tests/unit/name_compression_tests.cpp
        tests/unit/query_encoder_tests.cpp
        tests/unit/message_parser_tests.cpp
        tests/unit/endpoint_tests.cpp
        tests/unit/encrypted_endpoint_tests.cpp
        tests/unit/deadline_tests.cpp
        tests/unit/response_validator_tests.cpp)
    target_link_libraries(dnslab_tests PRIVATE dnslab_core Catch2::Catch2 CLI11::CLI11)
    dnslab_enable_warnings(dnslab_tests)

    # 这些用例需要系统套接字和回环网络，按运行条件与纯内存单元测试分开。
    add_executable(dnslab_integration_tests
        tests/main.cpp
        tests/unit/socket_tests.cpp
        tests/unit/udp_tests.cpp
        tests/integration/udp_query_tests.cpp
        tests/integration/tcp_transport_tests.cpp
        tests/integration/tcp_query_tests.cpp
        tests/integration/query_fallback_tests.cpp)
    target_include_directories(dnslab_integration_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    target_link_libraries(dnslab_integration_tests PRIVATE
        dnslab_core Catch2::Catch2 CLI11::CLI11 Threads::Threads)
    dnslab_enable_warnings(dnslab_integration_tests)

    include(cmake/DNSLabTests.cmake)
    dnslab_register_tests(dnslab dnslab_tests dnslab_integration_tests "${PROJECT_VERSION}")

    # 将同一套测试发现脚本随程序交付，运行环境无需再安装 Catch2 或编译器。
    find_file(dnslab_catch_module NAMES Catch.cmake
        PATHS ${CMAKE_MODULE_PATH} "${Catch2_DIR}"
        NO_DEFAULT_PATH NO_CACHE REQUIRED)
    get_filename_component(dnslab_catch_directory "${dnslab_catch_module}" DIRECTORY)
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-support")
    foreach(module Catch.cmake CatchAddTests.cmake)
        configure_file("${dnslab_catch_directory}/${module}"
            "${CMAKE_CURRENT_BINARY_DIR}/test-support/${module}" COPYONLY)
    endforeach()
    file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/dnslab-test-metadata.cmake" CONTENT
"set(DNSLAB_EXPECTED_VERSION \"${PROJECT_VERSION}\")
set(DNSLAB_CLI_FILENAME \"$<TARGET_FILE_NAME:dnslab>\")
set(DNSLAB_UNIT_FILENAME \"$<TARGET_FILE_NAME:dnslab_tests>\")
set(DNSLAB_INTEGRATION_FILENAME \"$<TARGET_FILE_NAME:dnslab_integration_tests>\")
")
endif()
