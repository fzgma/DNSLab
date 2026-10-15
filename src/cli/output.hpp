#pragma once

#include "app/encrypted_query.hpp"

#include <cstdio>
#include <string_view>

namespace dnslab::cli {

/// 向指定输出文件展示普通 DNS 查询的响应、记录与尝试过程。
void print_result(std::FILE* output, const app::QueryResult& result);

/// 向指定输出文件展示加密 DNS 查询的响应、记录与尝试过程。
void print_result(std::FILE* output, const app::EncryptedQueryResult& result);

/// 展示失败查询的上下文，并向错误输出文件写入中文原因。
void print_error(std::FILE* output, std::FILE* errors,
                 std::string_view target, std::string_view requested_transport,
                 const dns::DnsQuestion& question, const app::QueryError& error);

} // 命名空间 dnslab::cli
