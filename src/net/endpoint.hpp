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

    /// 比较地址族、地址字节及端口，不折叠 IPv4 映射地址。
    bool operator==(const Endpoint&) const = default;
    /// 根据地址变体返回 IPv4 或 IPv6 地址族。
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
    // 偏移针对原始输入；地址错误定位地址首字节，端口范围错误定位端口起点，
    // 重复端点的偏移固定为零。
    std::size_t offset;
};

struct EndpointListError {
    EndpointInputError error;
    std::size_t input_index;
    std::optional<std::size_t> first_duplicate_index;
};

/// 解析字面 IP 与可选端口，不解析主机名或探测网络。
[[nodiscard]] std::expected<Endpoint, EndpointInputError>
parse_endpoint(std::string_view input);

/// 输出带端口的规范端点，IPv6 使用方括号和小写十六进制。
[[nodiscard]] std::string format_endpoint(const Endpoint& endpoint);

/// 保持输入顺序并拒绝地址族、地址和端口均相同的重复端点。
[[nodiscard]] std::expected<std::vector<Endpoint>, EndpointListError>
parse_unique_endpoints(std::span<const std::string_view> inputs);

} // 命名空间 dnslab::net
