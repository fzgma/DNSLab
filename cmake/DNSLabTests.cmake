include_guard(GLOBAL)

include(Catch)

# Shared by the normal build and the compiler-free runtime project. Official
# Catch discovery handles escaping and invokes each case separately on its host.
function(dnslab_register_tests cli_target unit_target integration_target version)
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
endfunction()
