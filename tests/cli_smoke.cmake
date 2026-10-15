if(NOT DEFINED DNSLAB_EXECUTABLE OR NOT EXISTS "${DNSLAB_EXECUTABLE}")
    message(FATAL_ERROR "DNSLAB_EXECUTABLE 必须指向已经构建的 dnslab 程序")
endif()

if(NOT DEFINED DNSLAB_EXPECTED_VERSION OR DNSLAB_EXPECTED_VERSION STREQUAL "")
    message(FATAL_ERROR "必须由 CMake 提供 DNSLAB_EXPECTED_VERSION")
endif()

# 运行命令并核对退出码及中文参数错误说明。
function(run_cli label expected_code)
    execute_process(
        COMMAND "${DNSLAB_EXECUTABLE}" ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error_output
        TIMEOUT 5
        ENCODING UTF-8
    )
    if(NOT result STREQUAL "${expected_code}")
        message(FATAL_ERROR
            "${label}: 预期退出码 ${expected_code}，实际为 ${result}\n标准输出: ${output}\n标准错误: ${error_output}")
    endif()
    if(expected_code EQUAL 2 AND NOT error_output MATCHES "参数错误:")
        message(FATAL_ERROR "${label} 没有说明参数错误: ${error_output}")
    endif()
    set(cli_output "${output}" PARENT_SCOPE)
endfunction()

foreach(help_flag --help -h)
    run_cli("${help_flag}" 0 ${help_flag})
    if(NOT cli_output MATCHES "dnslab" OR NOT cli_output MATCHES "query"
       OR NOT cli_output MATCHES "--help" OR NOT cli_output MATCHES "--version")
        message(FATAL_ERROR "顶层帮助缺少已支持的命令: ${cli_output}")
    endif()
    run_cli("query ${help_flag}" 0 query ${help_flag})
    if(NOT cli_output MATCHES "选项" OR cli_output MATCHES "Print this help|POSITIONALS|OPTIONS|REQUIRED")
        message(FATAL_ERROR "查询帮助没有完整中文化: ${cli_output}")
    endif()
    foreach(option --server --doh --dot --type --transport --timeout-ms --ca-file)
        if(NOT cli_output MATCHES "${option}")
            message(FATAL_ERROR "查询帮助缺少 ${option}: ${cli_output}")
        endif()
    endforeach()
endforeach()

foreach(version_flag --version -V)
    run_cli("${version_flag}" 0 ${version_flag})
    string(STRIP "${cli_output}" version_output)
    if(NOT version_output STREQUAL "DNSLab ${DNSLAB_EXPECTED_VERSION}")
        message(FATAL_ERROR "版本输出不符合预期: ${version_output}")
    endif()
endforeach()

run_cli("无参数运行" 0)
if(NOT cli_output MATCHES "dnslab" OR NOT cli_output MATCHES "query"
   OR NOT cli_output MATCHES "--help" OR NOT cli_output MATCHES "--version")
    message(FATAL_ERROR "无参数运行未显示帮助: ${cli_output}")
endif()

run_cli("未知选项" 2 --dnslab-unknown-option)
run_cli("缺少查询名称和目标" 2 query)
run_cli("缺少查询名称" 2 query --server 127.0.0.1)
run_cli("缺少查询目标" 2 query example.com)
run_cli("查询名称多余" 2 query example.com example.net --server 127.0.0.1)
run_cli("比较命令尚未提供" 2 compare)
run_cli("报告选项尚未提供" 2 query example.com -s 127.0.0.1 --output report.json)
run_cli("覆盖选项尚未提供" 2 query example.com -s 127.0.0.1 --force)
run_cli("禁止跳过证书验证" 2 query example.com --doh https://127.0.0.1/dns-query --insecure)
run_cli("版本仅可在顶层查询" 2 query --version)

foreach(option --server --doh --dot --type --transport --timeout-ms --ca-file)
    run_cli("${option} 缺少选项值" 2 query example.com ${option})
endforeach()

run_cli("普通服务器与 DoH 冲突" 2 query example.com
    --server 127.0.0.1 --doh https://127.0.0.1/dns-query)
run_cli("普通服务器与 DoT 冲突" 2 query example.com --server 127.0.0.1 --dot 127.0.0.1)
run_cli("DoH 与 DoT 冲突" 2 query example.com
    --doh https://127.0.0.1/dns-query --dot 127.0.0.1)
foreach(mode auto udp tcp)
    run_cli("DoH 拒绝显式传输 ${mode}" 2 query example.com
        --doh https://127.0.0.1/dns-query --transport ${mode})
    run_cli("DoT 拒绝显式传输 ${mode}" 2 query example.com
        --dot 127.0.0.1 -T ${mode})
endforeach()
run_cli("普通 DNS 拒绝 CA 文件选项" 2 query example.com -s 127.0.0.1 --ca-file missing.pem)

run_cli("重复普通服务器选项" 2 query example.com --server 127.0.0.1 -s 127.0.0.1)
run_cli("重复 DoH 选项" 2 query example.com
    --doh https://127.0.0.1/dns-query --doh https://127.0.0.1/dns-query)
run_cli("重复 DoT 选项" 2 query example.com --dot 127.0.0.1 --dot 127.0.0.1)
run_cli("重复记录类型选项" 2 query example.com -s 127.0.0.1 --type A -t A)
run_cli("重复传输方式选项" 2 query example.com -s 127.0.0.1 --transport udp -T udp)
run_cli("重复超时选项" 2 query example.com -s 127.0.0.1 --timeout-ms 100 --timeout-ms 100)
run_cli("重复 CA 文件选项" 2 query example.com --dot 127.0.0.1
    --ca-file missing.pem --ca-file missing.pem)

foreach(name https://example.com 127.0.0.1 example..com example_com -example.com)
    run_cli("非法查询名称 ${name}" 2 query "${name}" --server 127.0.0.1)
endforeach()
foreach(endpoint localhost 127.0.0.1:0 127.0.0.1:65536 127.00.0.1)
    run_cli("非法普通服务器 ${endpoint}" 2 query example.com --server "${endpoint}")
endforeach()
run_cli("DoH 必须使用 HTTPS" 2 query example.com --doh http://127.0.0.1/dns-query)
run_cli("DoH 拒绝零端口" 2 query example.com --doh https://127.0.0.1:0/dns-query)
run_cli("DoT 拒绝 URL 形式" 2 query example.com --dot https://127.0.0.1)
run_cli("DoT 拒绝零端口" 2 query example.com --dot 127.0.0.1:0)
run_cli("不支持的记录类型" 2 query example.com --server 127.0.0.1 --type MX)
run_cli("非法传输方式" 2 query example.com --server 127.0.0.1 --transport TLS)
foreach(timeout 99 30001 +100 1.5 100x)
    run_cli("非法超时值 ${timeout}" 2 query example.com --server 127.0.0.1 --timeout-ms "${timeout}")
endforeach()

# 临时文件仅用于非法输入检查，不会被加入信任库。
get_filename_component(executable_directory "${DNSLAB_EXECUTABLE}" DIRECTORY)
string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef suffix)
set(invalid_ca "${executable_directory}/dnslab-invalid-ca-${suffix}.pem")
set(empty_ca "${executable_directory}/dnslab-empty-ca-${suffix}.pem")
set(missing_ca "${executable_directory}/dnslab-missing-ca-${suffix}.pem")
file(WRITE "${invalid_ca}" "无效的测试证书内容\n")
file(WRITE "${empty_ca}" "")
foreach(ca "${invalid_ca}" "${empty_ca}" "${missing_ca}" "${executable_directory}")
    run_cli("非法 CA 输入 ${ca}" 2 query example.com --doh https://127.0.0.1/dns-query --ca-file "${ca}")
endforeach()
file(REMOVE "${invalid_ca}" "${empty_ca}")
