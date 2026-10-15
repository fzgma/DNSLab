#include "app/encrypted_query.hpp"

#include "dns/wire_codec.hpp"

#include <limits>
#include <random>
#include <utility>

namespace dnslab::app {
namespace {

using Clock = net::Deadline::Clock;

std::chrono::microseconds elapsed_since(Clock::time_point started_at) {
    return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started_at);
}

QueryErrorCode classify(net::EncryptedErrorCode code) {
    switch (code) {
    case net::EncryptedErrorCode::TimedOut:
        return QueryErrorCode::Timeout;
    case net::EncryptedErrorCode::InvalidEndpoint:
        return QueryErrorCode::InvalidEndpoint;
    case net::EncryptedErrorCode::InvalidMessageLength:
    case net::EncryptedErrorCode::HttpStatus:
    case net::EncryptedErrorCode::InvalidContentType:
        return QueryErrorCode::InvalidResponse;
    default:
        return QueryErrorCode::Network;
    }
}

} // namespace

std::expected<EncryptedQueryResult, QueryError>
query_encrypted(const dns::DnsQuestion& question, const net::EncryptedEndpoint& server,
                std::chrono::milliseconds budget, const net::TlsOptions& tls,
                std::optional<std::uint16_t> transaction_id) {
    if (budget < std::chrono::milliseconds{100} ||
        budget > std::chrono::milliseconds{30000}) {
        return std::unexpected(QueryError{QueryErrorCode::InvalidTimeout});
    }
    std::expected<net::EncryptedEndpoint, net::EncryptedError> endpoint =
        std::unexpected(net::EncryptedError{net::EncryptedErrorCode::InvalidEndpoint});
    QueryTransport transport;
    switch (server.transport) {
    case net::EncryptedTransport::Doh:
        endpoint = net::parse_doh_endpoint(server.address);
        transport = QueryTransport::Doh;
        break;
    case net::EncryptedTransport::Dot:
        endpoint = net::parse_dot_endpoint(server.address);
        transport = QueryTransport::Dot;
        break;
    default:
        return std::unexpected(QueryError{QueryErrorCode::InvalidMode});
    }
    if (!endpoint) {
        return std::unexpected(QueryError{QueryErrorCode::InvalidEndpoint, endpoint.error()});
    }
    const auto validated = net::validate_tls_options(tls);
    if (!validated) {
        return std::unexpected(QueryError{QueryErrorCode::Network, validated.error()});
    }

    const auto started_at = Clock::now();
    const auto deadline = net::Deadline::after(budget, started_at);
    auto id = transaction_id.value_or(0);
    auto packet = dns::encode_query(question, id);
    if (!packet) {
        return std::unexpected(QueryError{
            QueryErrorCode::Encode, packet.error(), elapsed_since(started_at)});
    }
    if (!transaction_id && transport == QueryTransport::Dot) {
        try {
            std::random_device random;
            std::uniform_int_distribution<std::uint32_t> distribution{
                0, (std::numeric_limits<std::uint16_t>::max)()};
            id = static_cast<std::uint16_t>(distribution(random));
        } catch (...) {
            return std::unexpected(QueryError{
                QueryErrorCode::IdGeneration, {}, elapsed_since(started_at)});
        }
        (*packet)[0] = static_cast<std::byte>(id >> 8U);
        (*packet)[1] = static_cast<std::byte>(id & 0xffU);
    }
    if (deadline.expired()) {
        return std::unexpected(QueryError{
            QueryErrorCode::Timeout, {}, elapsed_since(started_at)});
    }

    const auto attempt_started = Clock::now();
    const auto failed = [&](QueryErrorCode code, QueryErrorDetail detail,
                             std::size_t ignored = 0) -> std::expected<EncryptedQueryResult, QueryError> {
        std::vector<QueryAttempt> attempts;
        attempts.push_back(QueryAttempt{
            transport, elapsed_since(attempt_started),
            std::unexpected(QueryFailure{code, detail}), ignored});
        return std::unexpected(QueryError{
            code, std::move(detail), elapsed_since(started_at), ignored, std::move(attempts)});
    };

    auto received = net::exchange_encrypted(*endpoint, *packet, deadline, tls);
    if (!received) {
        return failed(classify(received.error().code), received.error());
    }
    auto response = dns::parse_message(*received);
    if (!response) {
        return failed(QueryErrorCode::InvalidResponse, response.error(), 1);
    }
    const auto matched = validate_response(*response, question, id);
    if (!matched) {
        return failed(QueryErrorCode::InvalidResponse, matched.error(), 1);
    }
    if (deadline.expired()) {
        return failed(QueryErrorCode::Timeout,
            net::EncryptedError{net::EncryptedErrorCode::TimedOut});
    }
    std::vector<QueryAttempt> attempts;
    attempts.push_back(QueryAttempt{transport, elapsed_since(attempt_started), *response, 0});
    return EncryptedQueryResult{
        std::move(*endpoint), question, id, transport, std::move(*response),
        elapsed_since(started_at), 0, std::move(attempts)};
}

} // namespace dnslab::app
