#pragma once

#include "dns/errors.hpp"
#include "dns/types.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace dnslab::dns {

// Offsets identify the first byte to read; reading never advances a cursor.
[[nodiscard]] std::expected<std::uint16_t, DnsParseError>
read_u16_be(std::span<const std::byte> packet, std::size_t offset) noexcept;

[[nodiscard]] std::expected<std::uint32_t, DnsParseError>
read_u32_be(std::span<const std::byte> packet, std::size_t offset) noexcept;

void append_u16_be(Packet& packet, std::uint16_t value);
void append_u32_be(Packet& packet, std::uint32_t value);

} // namespace dnslab::dns
