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

add_library(dnslab_core STATIC
    src/dns/byte_utils.cpp
    src/dns/name_codec.cpp
    src/dns/query_encoder.cpp
    src/dns/message_parser.cpp)
target_include_directories(dnslab_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(dnslab_core PUBLIC cxx_std_23)

configure_file(cmake/version.hpp.in generated/dnslab/version.hpp @ONLY)
add_executable(dnslab src/main.cpp)
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
    add_executable(dnslab_tests
        tests/unit/byte_utils_tests.cpp
        tests/unit/dns_header_tests.cpp
        tests/unit/name_codec_tests.cpp
        tests/unit/name_compression_tests.cpp
        tests/unit/query_encoder_tests.cpp
        tests/unit/message_parser_tests.cpp)
    target_link_libraries(dnslab_tests PRIVATE dnslab_core Catch2::Catch2WithMain)
    dnslab_enable_warnings(dnslab_tests)

    include(Catch)
    catch_discover_tests(dnslab_tests PROPERTIES TIMEOUT 10)
    add_test(NAME dnslab_cli_smoke
        COMMAND "${CMAKE_COMMAND}"
            "-DDNSLAB_EXECUTABLE=$<TARGET_FILE:dnslab>"
            "-DDNSLAB_EXPECTED_VERSION=${PROJECT_VERSION}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.cmake")
    set_tests_properties(dnslab_cli_smoke PROPERTIES TIMEOUT 30)
endif()
