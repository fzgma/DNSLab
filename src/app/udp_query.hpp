#pragma once

#include "app/response_validator.hpp"
#include "dns/errors.hpp"
#include "dns/types.hpp"
#include "net/endpoint.hpp"
#include "net/errors.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <variant>

namespace dnslab::app {

struct UdpQueryResult {
    net::Endpoint server;
    dns::DnsQuestion question;
    std::uint16_t transaction_id;
    dns::DnsMessage response;
    std::chrono::microseconds elapsed;
    std::size_t ignored_datagrams{};
};

enum class UdpQueryErrorCode {
    InvalidTimeout,
    InvalidEndpoint,
    Encode,
    IdGeneration,
    Network,
    Timeout,
    InvalidResponse,
};

using UdpQueryErrorDetail = std::variant<std::monostate, dns::DnsEncodeError,
                                        net::NetworkError, dns::DnsParseError,
                                        ResponseMismatch>;

struct UdpQueryError {
    UdpQueryErrorCode code;
    // 响应无效时保留指定服务器最近一次被拒绝的响应详情。
    UdpQueryErrorDetail detail{};
    std::size_t ignored_datagrams{};
};

/// 在一个总预算内执行 UDP 查询并保留 TC 标志，不触发 TCP 回退。
// 准备、套接字创建和所有响应共享截止时间，无关数据报不会延长预算。
[[nodiscard]] std::expected<UdpQueryResult, UdpQueryError>
query_udp(const dns::DnsQuestion& question, const net::Endpoint& server,
          std::chrono::milliseconds budget = std::chrono::milliseconds{1500},
          std::optional<std::uint16_t> transaction_id = std::nullopt);

} // 命名空间 dnslab::app
