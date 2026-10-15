#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace dnslab::net {

enum class IpFamily { V4, V6 };

using Ipv4Address = std::array<std::byte, 4>;
using Ipv6Address = std::array<std::byte, 16>;
using IpAddress = std::variant<Ipv4Address, Ipv6Address>;

struct Endpoint {
    IpAddress address;
    std::uint16_t port{53};

    bool operator==(const Endpoint&) const = default;
    [[nodiscard]] IpFamily family() const noexcept;
};

enum class EndpointInputErrorCode {
    EmptyInput,
    InvalidCharacter,
    InvalidFormat,
    InvalidAddress,
    MissingPort,
    InvalidPort,
    PortOutOfRange,
    DuplicateEndpoint,
};

struct EndpointInputError {
    EndpointInputErrorCode code;
    // Offset in the original input; address errors identify its first byte,
    // port range errors identify the port start, and duplicates use zero.
    std::size_t offset;
};

struct EndpointListError {
    EndpointInputError error;
    std::size_t input_index;
    std::optional<std::size_t> first_duplicate_index;
};

[[nodiscard]] std::expected<Endpoint, EndpointInputError>
parse_endpoint(std::string_view input);

// Always includes the port; IPv6 uses brackets and lowercase hexadecimal.
[[nodiscard]] std::string format_endpoint(const Endpoint& endpoint);

// Preserves input order and rejects equivalent address/family/port tuples.
[[nodiscard]] std::expected<std::vector<Endpoint>, EndpointListError>
parse_unique_endpoints(std::span<const std::string_view> inputs);

} // namespace dnslab::net
