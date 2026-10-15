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
    // An empty label list is the root; labels otherwise retain raw octets.
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

    [[nodiscard]] constexpr bool is_response() const noexcept {
        return (flags & 0x8000U) != 0;
    }

    [[nodiscard]] constexpr std::uint8_t opcode() const noexcept {
        return static_cast<std::uint8_t>((flags >> 11) & 0x0fU);
    }

    [[nodiscard]] constexpr bool authoritative_answer() const noexcept {
        return (flags & 0x0400U) != 0;
    }

    [[nodiscard]] constexpr bool truncated() const noexcept {
        return (flags & 0x0200U) != 0;
    }

    [[nodiscard]] constexpr bool recursion_desired() const noexcept {
        return (flags & 0x0100U) != 0;
    }

    [[nodiscard]] constexpr bool recursion_available() const noexcept {
        return (flags & 0x0080U) != 0;
    }

    [[nodiscard]] constexpr bool authenticated_data() const noexcept {
        return (flags & 0x0020U) != 0;
    }

    [[nodiscard]] constexpr bool checking_disabled() const noexcept {
        return (flags & 0x0010U) != 0;
    }

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

} // namespace dnslab::dns
