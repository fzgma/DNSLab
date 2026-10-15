#pragma once

#include "dns/errors.hpp"
#include "dns/types.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace dnslab::dns {

/// 从指定偏移读取大端 16 位整数，且不推进调用方的游标。
[[nodiscard]] std::expected<std::uint16_t, DnsParseError>
read_u16_be(std::span<const std::byte> packet, std::size_t offset) noexcept;

/// 从指定偏移读取大端 32 位整数，越界时保留原请求偏移。
[[nodiscard]] std::expected<std::uint32_t, DnsParseError>
read_u32_be(std::span<const std::byte> packet, std::size_t offset) noexcept;

/// 将一个 16 位整数按大端顺序追加到报文末尾。
void append_u16_be(Packet& packet, std::uint16_t value);
/// 将一个 32 位整数按大端顺序追加到报文末尾。
void append_u32_be(Packet& packet, std::uint32_t value);

} // 命名空间 dnslab::dns
