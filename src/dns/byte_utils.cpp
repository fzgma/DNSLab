#include "dns/byte_utils.hpp"

namespace dnslab::dns {

/// 先验证剩余长度，再读取大端 16 位字段以避免偏移加法溢出。
std::expected<std::uint16_t, DnsParseError>
read_u16_be(std::span<const std::byte> packet, std::size_t offset) noexcept {
    if (offset > packet.size() || packet.size() - offset < 2) {
        return std::unexpected(DnsParseError{DnsParseErrorCode::FieldOutOfBounds, offset});
    }

    return static_cast<std::uint16_t>(
        (std::to_integer<std::uint16_t>(packet[offset]) << 8) |
        std::to_integer<std::uint16_t>(packet[offset + 1]));
}

/// 先验证剩余长度，再读取大端 32 位字段以避免偏移加法溢出。
std::expected<std::uint32_t, DnsParseError>
read_u32_be(std::span<const std::byte> packet, std::size_t offset) noexcept {
    if (offset > packet.size() || packet.size() - offset < 4) {
        return std::unexpected(DnsParseError{DnsParseErrorCode::FieldOutOfBounds, offset});
    }

    return (std::to_integer<std::uint32_t>(packet[offset]) << 24) |
           (std::to_integer<std::uint32_t>(packet[offset + 1]) << 16) |
           (std::to_integer<std::uint32_t>(packet[offset + 2]) << 8) |
           std::to_integer<std::uint32_t>(packet[offset + 3]);
}

/// 按高字节在前的顺序追加 16 位整数。
void append_u16_be(Packet& packet, std::uint16_t value) {
    packet.push_back(static_cast<std::byte>((value >> 8) & 0xffU));
    packet.push_back(static_cast<std::byte>(value & 0xffU));
}

/// 按高字节在前的顺序追加 32 位整数。
void append_u32_be(Packet& packet, std::uint32_t value) {
    packet.push_back(static_cast<std::byte>((value >> 24) & 0xffU));
    packet.push_back(static_cast<std::byte>((value >> 16) & 0xffU));
    packet.push_back(static_cast<std::byte>((value >> 8) & 0xffU));
    packet.push_back(static_cast<std::byte>(value & 0xffU));
}

} // 命名空间 dnslab::dns
