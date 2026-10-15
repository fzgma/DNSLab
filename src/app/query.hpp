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
    // A matching TC response remains a successful UDP attempt even when the
    // subsequent TCP attempt fails; it does not make the overall query succeed.
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

// One ID, encoded query and absolute deadline cover all preparation and attempts.
// Auto falls back only after a complete, matching UDP response with TC set.
// Malformed DNS messages in complete TCP frames can be ignored. Invalid framing
// terminates with InvalidResponse and the original NetworkError; EOF and other
// transport failures remain Network errors even after an earlier bad response.
[[nodiscard]] std::expected<QueryResult, QueryError>
query_server(const dns::DnsQuestion& question, const net::Endpoint& server,
             TransportMode mode = TransportMode::Auto,
             std::chrono::milliseconds budget = std::chrono::milliseconds{1500},
             std::optional<std::uint16_t> transaction_id = std::nullopt);

} // namespace dnslab::app
