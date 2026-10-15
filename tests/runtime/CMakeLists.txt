cmake_minimum_required(VERSION 3.25)
project(DNSLabRuntimeTests LANGUAGES NONE)

enable_testing()

# Register the existing programs without finding a compiler, dependencies or a
# build tool. CI runs each label with --output-on-failure --no-tests=error.
if(NOT DNSLAB_BUILD_DIR)
    message(FATAL_ERROR "DNSLAB_BUILD_DIR must identify the compiled artifact directory")
endif()
get_filename_component(DNSLAB_BUILD_DIR "${DNSLAB_BUILD_DIR}" ABSOLUTE
    BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/../..")

set(metadata "${DNSLAB_BUILD_DIR}/dnslab-test-metadata.cmake")
if(NOT EXISTS "${metadata}")
    message(FATAL_ERROR "Missing build metadata: ${metadata}")
endif()
include("${metadata}")

foreach(variable DNSLAB_EXPECTED_VERSION DNSLAB_CLI_FILENAME DNSLAB_UNIT_FILENAME
                 DNSLAB_INTEGRATION_FILENAME)
    if(NOT DEFINED ${variable} OR "${${variable}}" STREQUAL "")
        message(FATAL_ERROR "Build metadata must define ${variable}")
    endif()
endforeach()

foreach(module Catch.cmake CatchAddTests.cmake)
    if(NOT EXISTS "${DNSLAB_BUILD_DIR}/test-support/${module}")
        message(FATAL_ERROR "Missing runtime discovery helper: test-support/${module}")
    endif()
endforeach()
list(PREPEND CMAKE_MODULE_PATH "${DNSLAB_BUILD_DIR}/test-support")

function(import_test_program target filename)
    set(program "${DNSLAB_BUILD_DIR}/${filename}")
    if(NOT EXISTS "${program}" OR IS_DIRECTORY "${program}")
        message(FATAL_ERROR "Missing compiled program: ${program}")
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
