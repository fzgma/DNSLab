#pragma once

#include "dns/errors.hpp"
#include "dns/types.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace dnslab::dns {

/// 解析 ASCII 主机名与可选尾点，允许根名，并在语法和长度检查后拒绝纯数字点串。
[[nodiscard]] std::expected<DnsName, NameInputError>
parse_ascii_name(std::string_view input);

/// 校验标签及报文长度后编码名称，保留标签中的任意原始字节。
[[nodiscard]] std::expected<EncodedName, DnsEncodeError>
encode_name(const DnsName& name);

/// 基于完整报文解码普通标签和向后压缩指针，返回名称及原路径消费长度。
// consumed 只累计起始路径的字节，并包含遇到的首个压缩指针。
// 错误定位违规长度字节、指针或重复游标；缺失长度字节时保留请求游标。
[[nodiscard]] std::expected<DecodedName, DnsParseError>
decode_name(std::span<const std::byte> packet, std::size_t start);

/// 输出带尾点的名称，并用三位十进制转义不安全字节。
[[nodiscard]] std::string format_name(const DnsName& name);

/// 按标签逐字节比较名称，仅忽略 ASCII 字母大小写。
[[nodiscard]] bool names_equal_case_insensitive(const DnsName& a,
                                                const DnsName& b) noexcept;

} // 命名空间 dnslab::dns
