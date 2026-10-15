#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace dnslab::dns {

using Packet = std::vector<std::byte>;

struct DnsName {
    // 空标签列表表示根名；其他标签保留原始字节。
    std::vector<std::string> labels;
};

struct EncodedName {
    Packet bytes;
};

struct DecodedName {
    DnsName name;
    std::size_t consumed;
};

struct DnsHeader {
    std::uint16_t id{};
    std::uint16_t flags{};

    /// 读取 QR 位，判断报文是否为响应。
    [[nodiscard]] constexpr bool is_response() const noexcept {
        return (flags & 0x8000U) != 0;
    }

    /// 提取原始标志中的四位操作码。
    [[nodiscard]] constexpr std::uint8_t opcode() const noexcept {
        return static_cast<std::uint8_t>((flags >> 11) & 0x0fU);
    }

    /// 读取 AA 位，判断响应是否声明为权威应答。
    [[nodiscard]] constexpr bool authoritative_answer() const noexcept {
        return (flags & 0x0400U) != 0;
    }

    /// 读取 TC 位，判断报文是否被截断。
    [[nodiscard]] constexpr bool truncated() const noexcept {
        return (flags & 0x0200U) != 0;
    }

    /// 读取 RD 位，判断请求是否要求递归解析。
    [[nodiscard]] constexpr bool recursion_desired() const noexcept {
        return (flags & 0x0100U) != 0;
    }

    /// 读取 RA 位，判断服务器是否声明支持递归解析。
    [[nodiscard]] constexpr bool recursion_available() const noexcept {
        return (flags & 0x0080U) != 0;
    }

    /// 读取 AD 位，保留服务器对数据已验证的声明。
    [[nodiscard]] constexpr bool authenticated_data() const noexcept {
        return (flags & 0x0020U) != 0;
    }

    /// 读取 CD 位，判断请求是否禁用服务器的 DNSSEC 检查。
    [[nodiscard]] constexpr bool checking_disabled() const noexcept {
        return (flags & 0x0010U) != 0;
    }

    /// 提取报文头中的四位响应码，不包含 EDNS 扩展位。
    [[nodiscard]] constexpr std::uint8_t rcode() const noexcept {
        return static_cast<std::uint8_t>(flags & 0x000fU);
    }
};

struct DnsQuestion {
    DnsName name;
    std::uint16_t type{};
    std::uint16_t qclass{};
};

struct AData {
    std::array<std::byte, 4> address{};
};

struct AaaaData {
    std::array<std::byte, 16> address{};
};

struct NameData {
    DnsName name;
};

struct OpaqueData {
    Packet bytes;
};

using RData = std::variant<AData, AaaaData, NameData, OpaqueData>;

struct ResourceRecord {
    DnsName owner;
    std::uint16_t type{};
    std::uint16_t rr_class{};
    std::uint32_t ttl{};
    RData rdata;
};

struct DnsMessage {
    DnsHeader header;
    std::vector<DnsQuestion> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authority;
    std::vector<ResourceRecord> additional;
};

} // 命名空间 dnslab::dns
