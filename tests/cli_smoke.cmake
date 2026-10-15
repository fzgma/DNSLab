if(NOT DEFINED DNSLAB_EXECUTABLE OR NOT EXISTS "${DNSLAB_EXECUTABLE}")
    message(FATAL_ERROR "DNSLAB_EXECUTABLE must name a built dnslab executable")
endif()

if(NOT DEFINED DNSLAB_EXPECTED_VERSION OR DNSLAB_EXPECTED_VERSION STREQUAL "")
    message(FATAL_ERROR "DNSLAB_EXPECTED_VERSION must be supplied by CMake")
endif()

function(run_cli label expected_code)
    execute_process(
        COMMAND "${DNSLAB_EXECUTABLE}" ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error_output
        TIMEOUT 5
    )
    if(NOT result STREQUAL "${expected_code}")
        message(FATAL_ERROR
            "${label}: expected exit ${expected_code}, got ${result}\nstdout: ${output}\nstderr: ${error_output}")
    endif()
    if(expected_code EQUAL 2 AND NOT error_output MATCHES "Argument error:")
        message(FATAL_ERROR "${label} did not explain the argument error: ${error_output}")
    endif()
    set(cli_output "${output}" PARENT_SCOPE)
endfunction()

foreach(help_flag --help -h)
    run_cli("${help_flag}" 0 ${help_flag})
    if(NOT cli_output MATCHES "dnslab" OR NOT cli_output MATCHES "query"
       OR NOT cli_output MATCHES "--help" OR NOT cli_output MATCHES "--version")
        message(FATAL_ERROR "Top-level help omitted supported commands: ${cli_output}")
    endif()
    run_cli("query ${help_flag}" 0 query ${help_flag})
    foreach(option --server --doh --dot --type --transport --timeout-ms --ca-file)
        if(NOT cli_output MATCHES "${option}")
            message(FATAL_ERROR "Query help omitted ${option}: ${cli_output}")
        endif()
    endforeach()
endforeach()

foreach(version_flag --version -V)
    run_cli("${version_flag}" 0 ${version_flag})
    string(STRIP "${cli_output}" version_output)
    if(NOT version_output STREQUAL "DNSLab ${DNSLAB_EXPECTED_VERSION}")
        message(FATAL_ERROR "Unexpected version output: ${version_output}")
    endif()
endforeach()

run_cli("no arguments" 0)
if(NOT cli_output MATCHES "dnslab" OR NOT cli_output MATCHES "query"
   OR NOT cli_output MATCHES "--help" OR NOT cli_output MATCHES "--version")
    message(FATAL_ERROR "Running without arguments did not show help: ${cli_output}")
endif()

run_cli("unknown option" 2 --dnslab-unknown-option)
run_cli("missing query name and target" 2 query)
run_cli("missing query name" 2 query --server 127.0.0.1)
run_cli("missing target" 2 query example.com)
run_cli("extra query name" 2 query example.com example.net --server 127.0.0.1)
run_cli("compare remains unavailable" 2 compare)
run_cli("output remains unavailable" 2 query example.com -s 127.0.0.1 --output report.json)
run_cli("force remains unavailable" 2 query example.com -s 127.0.0.1 --force)
run_cli("insecure is unavailable" 2 query example.com --doh https://127.0.0.1/dns-query --insecure)
run_cli("version is a top-level option" 2 query --version)

foreach(option --server --doh --dot --type --transport --timeout-ms --ca-file)
    run_cli("missing value for ${option}" 2 query example.com ${option})
endforeach()

run_cli("server and doh conflict" 2 query example.com
    --server 127.0.0.1 --doh https://127.0.0.1/dns-query)
run_cli("server and dot conflict" 2 query example.com --server 127.0.0.1 --dot 127.0.0.1)
run_cli("doh and dot conflict" 2 query example.com
    --doh https://127.0.0.1/dns-query --dot 127.0.0.1)
foreach(mode auto udp tcp)
    run_cli("doh rejects explicit ${mode}" 2 query example.com
        --doh https://127.0.0.1/dns-query --transport ${mode})
    run_cli("dot rejects explicit ${mode}" 2 query example.com
        --dot 127.0.0.1 -T ${mode})
endforeach()
run_cli("plain DNS rejects ca-file" 2 query example.com -s 127.0.0.1 --ca-file missing.pem)

run_cli("duplicate server" 2 query example.com --server 127.0.0.1 -s 127.0.0.1)
run_cli("duplicate doh" 2 query example.com
    --doh https://127.0.0.1/dns-query --doh https://127.0.0.1/dns-query)
run_cli("duplicate dot" 2 query example.com --dot 127.0.0.1 --dot 127.0.0.1)
run_cli("duplicate type" 2 query example.com -s 127.0.0.1 --type A -t A)
run_cli("duplicate transport" 2 query example.com -s 127.0.0.1 --transport udp -T udp)
run_cli("duplicate timeout" 2 query example.com -s 127.0.0.1 --timeout-ms 100 --timeout-ms 100)
run_cli("duplicate ca-file" 2 query example.com --dot 127.0.0.1
    --ca-file missing.pem --ca-file missing.pem)

foreach(name https://example.com 127.0.0.1 example..com example_com -example.com)
    run_cli("invalid name ${name}" 2 query "${name}" --server 127.0.0.1)
endforeach()
foreach(endpoint localhost 127.0.0.1:0 127.0.0.1:65536 127.00.0.1)
    run_cli("invalid server ${endpoint}" 2 query example.com --server "${endpoint}")
endforeach()
run_cli("doh requires https" 2 query example.com --doh http://127.0.0.1/dns-query)
run_cli("doh rejects port zero" 2 query example.com --doh https://127.0.0.1:0/dns-query)
run_cli("dot rejects a URL" 2 query example.com --dot https://127.0.0.1)
run_cli("dot rejects port zero" 2 query example.com --dot 127.0.0.1:0)
run_cli("unsupported record type" 2 query example.com --server 127.0.0.1 --type MX)
run_cli("invalid transport" 2 query example.com --server 127.0.0.1 --transport TLS)
foreach(timeout 99 30001 +100 1.5 100x)
    run_cli("invalid timeout ${timeout}" 2 query example.com --server 127.0.0.1 --timeout-ms "${timeout}")
endforeach()

# Temporary input files stay beside the built executable and are never trusted.
get_filename_component(executable_directory "${DNSLAB_EXECUTABLE}" DIRECTORY)
string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef suffix)
set(invalid_ca "${executable_directory}/dnslab-invalid-ca-${suffix}.pem")
set(empty_ca "${executable_directory}/dnslab-empty-ca-${suffix}.pem")
set(missing_ca "${executable_directory}/dnslab-missing-ca-${suffix}.pem")
file(WRITE "${invalid_ca}" "not a PEM certificate\n")
file(WRITE "${empty_ca}" "")
foreach(ca "${invalid_ca}" "${empty_ca}" "${missing_ca}" "${executable_directory}")
    run_cli("invalid CA input ${ca}" 2 query example.com --doh https://127.0.0.1/dns-query --ca-file "${ca}")
endforeach()
file(REMOVE "${invalid_ca}" "${empty_ca}")
