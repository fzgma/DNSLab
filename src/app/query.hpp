#pragma once

#include "app/response_validator.hpp"
#include "dns/errors.hpp"
#include "dns/types.hpp"
#include "net/endpoint.hpp"
#include "net/encrypted_transport.hpp"
#include "net/errors.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <variant>
#include <vector>

namespace dnslab::app {

enum class TransportMode { Auto, Udp, Tcp };
enum class QueryTransport { Udp, Tcp, Doh, Dot };

enum class QueryErrorCode {
    InvalidMode,
    InvalidTimeout,
    InvalidEndpoint,
    Encode,
    IdGeneration,
    Network,
    Timeout,
    InvalidResponse,
};

using QueryErrorDetail = std::variant<std::monostate, dns::DnsEncodeError,
                                     net::NetworkError, dns::DnsParseError,
                                     ResponseMismatch, net::EncryptedError>;

struct QueryFailure {
    QueryErrorCode code;
    QueryErrorDetail detail{};
};

struct QueryAttempt {
    QueryTransport transport;
    std::chrono::microseconds elapsed;
    // 即使后续 TCP 失败，匹配的截断 UDP 响应仍保留为成功尝试；整体查询以最后尝试为准。
    std::expected<dns::DnsMessage, QueryFailure> outcome;
    std::size_t ignored_messages{};
};

struct QueryResult {
    net::Endpoint server;
    dns::DnsQuestion question;
    std::uint16_t transaction_id;
    QueryTransport transport;
    dns::DnsMessage response;
    std::chrono::microseconds elapsed;
    std::size_t ignored_messages{};
    std::vector<QueryAttempt> attempts{};
};

struct QueryError {
    QueryErrorCode code;
    QueryErrorDetail detail{};
    std::chrono::microseconds elapsed{};
    std::size_t ignored_messages{};
    std::vector<QueryAttempt> attempts{};
};

/// 在同一事务 ID、查询报文和截止时间下执行单服务器查询及必要的截断回退。
// 自动模式仅在完整且匹配的 UDP 响应带 TC 时回退。
// 完整 TCP 帧内的无效 DNS 响应可被忽略；帧长度错误则保留网络详情并终止为无效响应。
// 连接关闭和其他收发失败始终保留网络原因，不被此前收到的坏响应掩盖。
[[nodiscard]] std::expected<QueryResult, QueryError>
query_server(const dns::DnsQuestion& question, const net::Endpoint& server,
             TransportMode mode = TransportMode::Auto,
             std::chrono::milliseconds budget = std::chrono::milliseconds{1500},
             std::optional<std::uint16_t> transaction_id = std::nullopt);

} // 命名空间 dnslab::app
