include_guard(GLOBAL)

include(Catch)

# Shared by the normal build and the compiler-free runtime project. Official
# Catch discovery handles escaping and invokes each case separately on its host.
function(dnslab_register_tests cli_target unit_target integration_target version)
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    catch_discover_tests(${unit_target}
        DISCOVERY_MODE PRE_TEST
        SKIP_IS_FAILURE
        PROPERTIES TIMEOUT 10 LABELS unit)
    catch_discover_tests(${integration_target}
        DISCOVERY_MODE PRE_TEST
        SKIP_IS_FAILURE
        PROPERTIES TIMEOUT 10 LABELS integration)

    add_test(NAME dnslab_cli_smoke
        COMMAND "${CMAKE_COMMAND}"
            "-DDNSLAB_EXECUTABLE=$<TARGET_FILE:${cli_target}>"
            "-DDNSLAB_EXPECTED_VERSION=${version}"
            -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tests/cli_smoke.cmake")
    set_tests_properties(dnslab_cli_smoke PROPERTIES TIMEOUT 30 LABELS smoke)

    foreach(suite encrypted_query plain_query_cli)
        set(script "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tests/integration/${suite}_tests.py")
        execute_process(COMMAND "${Python3_EXECUTABLE}" "${script}" --list-cases
            RESULT_VARIABLE discovery_result OUTPUT_VARIABLE cases
            ERROR_VARIABLE discovery_error OUTPUT_STRIP_TRAILING_WHITESPACE)
        if(NOT discovery_result EQUAL 0 OR cases STREQUAL "")
            message(FATAL_ERROR "${suite} test discovery failed: ${discovery_error}")
        endif()
        string(REPLACE "\r\n" "\n" cases "${cases}")
        string(REPLACE "\n" ";" cases "${cases}")
        foreach(case IN LISTS cases)
            if(NOT case MATCHES "^[a-z0-9_]+$")
                message(FATAL_ERROR "Invalid ${suite} test name: ${case}")
            endif()
            add_test(NAME "cli_${case}"
                COMMAND "${Python3_EXECUTABLE}" "${script}"
                    --executable "$<TARGET_FILE:${cli_target}>" --case "${case}")
            set_tests_properties("cli_${case}" PROPERTIES TIMEOUT 10 LABELS integration)
            if(suite STREQUAL "encrypted_query")
                set_tests_properties("cli_${case}" PROPERTIES RESOURCE_LOCK dnslab_test_crl)
            endif()
        endforeach()
    endforeach()
endfunction()
