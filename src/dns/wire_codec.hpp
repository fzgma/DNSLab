#pragma once

#include "dns/errors.hpp"
#include "dns/types.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace dnslab::dns {

/// 解析一份完整 DNS 报文，压缩指针始终以整个报文为基准。
[[nodiscard]] std::expected<DnsMessage, DnsParseError>
parse_message(std::span<const std::byte> packet);

/// 使用调用方事务 ID 编码一个支持类型的未压缩 IN 查询。
// 先检查名称，再检查查询类型和类别，以保持错误优先级。
[[nodiscard]] std::expected<Packet, DnsEncodeError>
encode_query(const DnsQuestion& question, std::uint16_t transaction_id,
             bool recursion_desired = true);

} // 命名空间 dnslab::dns
