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
    // InvalidResponse retains the latest rejection from the requested server.
    UdpQueryErrorDetail detail{};
    std::size_t ignored_datagrams{};
};

// Sends one UDP query. One deadline covers preparation, socket creation and all
// responses; unrelated datagrams do not renew it. TC is retained without fallback.
[[nodiscard]] std::expected<UdpQueryResult, UdpQueryError>
query_udp(const dns::DnsQuestion& question, const net::Endpoint& server,
          std::chrono::milliseconds budget = std::chrono::milliseconds{1500},
          std::optional<std::uint16_t> transaction_id = std::nullopt);

} // namespace dnslab::app
