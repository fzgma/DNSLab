#pragma once

#include "app/compare.hpp"
#include "app/encrypted_query.hpp"

#include <cstdio>
#include <string_view>

namespace dnslab::cli {

/// 向指定输出文件展示普通 DNS 查询的响应、记录与尝试过程。
void print_result(std::FILE* output, const app::QueryResult& result);

/// 向指定输出文件展示加密 DNS 查询的响应、记录与尝试过程。
void print_result(std::FILE* output, const app::EncryptedQueryResult& result);

/// 展示全部比较结果，并以首个成功响应为参照输出差异摘要。
void print_comparison(std::FILE* output, std::FILE* errors, const app::CompareResult& result);

/// 展示失败查询的上下文，并向错误输出文件写入中文原因。
void print_error(std::FILE* output, std::FILE* errors,
                 std::string_view target, std::string_view requested_transport,
                 const dns::DnsQuestion& question, const app::QueryError& error);

} // 命名空间 dnslab::cli
