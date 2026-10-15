if(NOT DEFINED DNSLAB_EXECUTABLE OR NOT EXISTS "${DNSLAB_EXECUTABLE}")
    message(FATAL_ERROR "DNSLAB_EXECUTABLE must name a built dnslab executable")
endif()

if(NOT DEFINED DNSLAB_EXPECTED_VERSION OR DNSLAB_EXPECTED_VERSION STREQUAL "")
    message(FATAL_ERROR "DNSLAB_EXPECTED_VERSION must be supplied by CMake")
endif()

function(run_cli label expect_success)
    execute_process(
        COMMAND "${DNSLAB_EXECUTABLE}" ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error_output
        TIMEOUT 5
    )

    if(expect_success)
        if(NOT result STREQUAL "0")
            message(FATAL_ERROR
                "${label} failed (${result})\nstdout: ${output}\nstderr: ${error_output}")
        endif()
    elseif(NOT result MATCHES "^[1-9][0-9]*$")
        message(FATAL_ERROR
            "${label} must report a CLI error (${result})\nstdout: ${output}\nstderr: ${error_output}")
    endif()

    set(cli_output "${output}" PARENT_SCOPE)
endfunction()

run_cli("--help" TRUE --help)
if(NOT cli_output MATCHES "OPTIONS" OR NOT cli_output MATCHES "dnslab"
   OR NOT cli_output MATCHES "--help" OR NOT cli_output MATCHES "--version")
    message(FATAL_ERROR "--help did not describe the supported CLI: ${cli_output}")
endif()

run_cli("--version" TRUE --version)
string(STRIP "${cli_output}" version_output)
if(NOT version_output STREQUAL "DNSLab ${DNSLAB_EXPECTED_VERSION}")
    message(FATAL_ERROR "Unexpected --version output: ${version_output}")
endif()

run_cli("no arguments" TRUE)
if(NOT cli_output MATCHES "OPTIONS" OR NOT cli_output MATCHES "dnslab"
   OR NOT cli_output MATCHES "--help" OR NOT cli_output MATCHES "--version")
    message(FATAL_ERROR "Running without arguments did not show help: ${cli_output}")
endif()

run_cli("unknown option" FALSE --dnslab-unknown-option)
run_cli("query is not implemented" FALSE query)
run_cli("compare is not implemented" FALSE compare)
