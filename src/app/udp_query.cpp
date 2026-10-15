#include "app/udp_query.hpp"

#include "app/query.hpp"

#include <utility>

namespace dnslab::app {
namespace {

UdpQueryErrorCode udp_error_code(QueryErrorCode code) noexcept {
    switch (code) {
    case QueryErrorCode::InvalidTimeout:
        return UdpQueryErrorCode::InvalidTimeout;
    case QueryErrorCode::InvalidEndpoint:
        return UdpQueryErrorCode::InvalidEndpoint;
    case QueryErrorCode::Encode:
        return UdpQueryErrorCode::Encode;
    case QueryErrorCode::IdGeneration:
        return UdpQueryErrorCode::IdGeneration;
    case QueryErrorCode::Network:
        return UdpQueryErrorCode::Network;
    case QueryErrorCode::Timeout:
        return UdpQueryErrorCode::Timeout;
    case QueryErrorCode::InvalidResponse:
        return UdpQueryErrorCode::InvalidResponse;
    case QueryErrorCode::InvalidMode:
        // The only caller below always supplies the valid Udp mode.
        std::unreachable();
    }
    std::unreachable();
}

} // namespace

std::expected<UdpQueryResult, UdpQueryError>
query_udp(const dns::DnsQuestion& question, const net::Endpoint& server,
          std::chrono::milliseconds budget,
          std::optional<std::uint16_t> transaction_id) {
    auto result = query_server(question, server, TransportMode::Udp, budget, transaction_id);
    if (!result) {
        const auto& error = result.error();
        return std::unexpected(UdpQueryError{
            udp_error_code(error.code), error.detail, error.ignored_messages});
    }
    return UdpQueryResult{
        std::move(result->server), std::move(result->question), result->transaction_id,
        std::move(result->response), result->elapsed, result->ignored_messages};
}

} // namespace dnslab::app
