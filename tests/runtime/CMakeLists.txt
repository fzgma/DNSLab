cmake_minimum_required(VERSION 3.25)
project(DNSLabRuntimeTests LANGUAGES NONE)

enable_testing()

# 只注册已有程序，不查找编译器或构建依赖；持续集成逐个执行测试标签。
if(NOT DNSLAB_BUILD_DIR)
    message(FATAL_ERROR "请通过 DNSLAB_BUILD_DIR 指定已编译产物所在目录。")
endif()
get_filename_component(DNSLAB_BUILD_DIR "${DNSLAB_BUILD_DIR}" ABSOLUTE
    BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/../..")

set(metadata "${DNSLAB_BUILD_DIR}/dnslab-test-metadata.cmake")
if(NOT EXISTS "${metadata}")
    message(FATAL_ERROR "缺少构建元数据：${metadata}")
endif()
include("${metadata}")

foreach(variable DNSLAB_EXPECTED_VERSION DNSLAB_CLI_FILENAME DNSLAB_UNIT_FILENAME
                 DNSLAB_INTEGRATION_FILENAME)
    if(NOT DEFINED ${variable} OR "${${variable}}" STREQUAL "")
        message(FATAL_ERROR "构建元数据必须定义 ${variable}。")
    endif()
endforeach()

foreach(module Catch.cmake CatchAddTests.cmake)
    if(NOT EXISTS "${DNSLAB_BUILD_DIR}/test-support/${module}")
        message(FATAL_ERROR "缺少运行时测试发现脚本：test-support/${module}")
    endif()
endforeach()
list(PREPEND CMAKE_MODULE_PATH "${DNSLAB_BUILD_DIR}/test-support")

# 将已有可执行文件导入为测试目标，不生成或重新编译程序。
function(import_test_program target filename)
    set(program "${DNSLAB_BUILD_DIR}/${filename}")
    if(NOT EXISTS "${program}" OR IS_DIRECTORY "${program}")
        message(FATAL_ERROR "缺少已编译程序：${program}")
    endif()
    add_executable(${target} IMPORTED GLOBAL)
    set_target_properties(${target} PROPERTIES IMPORTED_LOCATION "${program}")
endfunction()

import_test_program(dnslab "${DNSLAB_CLI_FILENAME}")
import_test_program(dnslab_tests "${DNSLAB_UNIT_FILENAME}")
import_test_program(dnslab_integration_tests "${DNSLAB_INTEGRATION_FILENAME}")

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/DNSLabTests.cmake")
dnslab_register_tests(dnslab dnslab_tests dnslab_integration_tests
    "${DNSLAB_EXPECTED_VERSION}")
