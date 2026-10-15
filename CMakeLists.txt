cmake_minimum_required(VERSION 3.25)

project(DNSLab VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)
include(CheckCXXSourceCompiles)

check_cxx_source_compiles([[
    #include <expected>
    #if !defined(__cpp_lib_expected) || __cpp_lib_expected < 202202L
    #error A C++23 standard library with std::expected is required.
    #endif
    int main() {
        std::expected<int, int> value{42};
        return value.value() == 42 ? 0 : 1;
    }
]] DNSLAB_HAS_STD_EXPECTED)
if(NOT DNSLAB_HAS_STD_EXPECTED)
    message(FATAL_ERROR "DNSLab requires a C++23 compiler and standard library with std::expected.")
endif()

find_package(CLI11 CONFIG REQUIRED)
find_package(CURL CONFIG REQUIRED)

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
target_link_libraries(dnslab_core PRIVATE CURL::libcurl)
if(WIN32)
    target_link_libraries(dnslab_core PUBLIC ws2_32)
endif()

configure_file(cmake/version.hpp.in generated/dnslab/version.hpp @ONLY)
add_executable(dnslab src/main.cpp src/cli/output.cpp)
target_include_directories(dnslab PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(dnslab PRIVATE dnslab_core CLI11::CLI11)

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
    find_package(Catch2 3 CONFIG REQUIRED)
    find_package(Threads REQUIRED)
    add_executable(dnslab_tests
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
    target_link_libraries(dnslab_tests PRIVATE dnslab_core Catch2::Catch2WithMain)
    dnslab_enable_warnings(dnslab_tests)

    # These suites exercise OS sockets and loopback networking, regardless of
    # their original source directory. Keep pure unit execution independent.
    add_executable(dnslab_integration_tests
        tests/unit/socket_tests.cpp
        tests/unit/udp_tests.cpp
        tests/integration/udp_query_tests.cpp
        tests/integration/tcp_transport_tests.cpp
        tests/integration/tcp_query_tests.cpp
        tests/integration/query_fallback_tests.cpp)
    target_include_directories(dnslab_integration_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    target_link_libraries(dnslab_integration_tests PRIVATE
        dnslab_core Catch2::Catch2WithMain Threads::Threads)
    dnslab_enable_warnings(dnslab_integration_tests)

    include(cmake/DNSLabTests.cmake)
    dnslab_register_tests(dnslab dnslab_tests dnslab_integration_tests "${PROJECT_VERSION}")

    # Runtime validation uses these exact Catch discovery helpers alongside the
    # compiled programs, without installing Catch2 or a C++ toolchain again.
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
