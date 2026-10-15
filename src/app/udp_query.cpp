#include "app/udp_query.hpp"

#include "dns/wire_codec.hpp"
#include "net/deadline.hpp"
#include "net/socket.hpp"
#include "net/udp.hpp"

#include <limits>
#include <random>
#include <utility>

namespace dnslab::app {
namespace {

std::unexpected<UdpQueryError> timeout_error(
    const UdpQueryErrorDetail& last_rejection, std::size_t ignored) {
    if (!std::holds_alternative<std::monostate>(last_rejection)) {
        return std::unexpected(UdpQueryError{
            UdpQueryErrorCode::InvalidResponse, last_rejection, ignored});
    }
    return std::unexpected(UdpQueryError{UdpQueryErrorCode::Timeout, {}, ignored});
}

std::unexpected<UdpQueryError> network_error(net::NetworkError error,
                                            std::size_t ignored = 0) {
    return std::unexpected(UdpQueryError{UdpQueryErrorCode::Network, error, ignored});
}

} // namespace

std::expected<UdpQueryResult, UdpQueryError>
query_udp(const dns::DnsQuestion& question, const net::Endpoint& server,
          std::chrono::milliseconds budget,
          std::optional<std::uint16_t> transaction_id) {
    if (budget < std::chrono::milliseconds{100} ||
        budget > std::chrono::milliseconds{30000}) {
        return std::unexpected(UdpQueryError{UdpQueryErrorCode::InvalidTimeout});
    }
    if (server.port == 0) {
        return std::unexpected(UdpQueryError{UdpQueryErrorCode::InvalidEndpoint});
    }

    const auto started_at = net::Deadline::Clock::now();
    const auto deadline = net::Deadline::after(budget, started_at);
    auto id = transaction_id.value_or(0);
    auto packet = dns::encode_query(question, id);
    if (!packet) {
        return std::unexpected(UdpQueryError{UdpQueryErrorCode::Encode, packet.error()});
    }

    if (!transaction_id) {
        try {
            std::random_device random;
            std::uniform_int_distribution<std::uint32_t> distribution{
                0, std::numeric_limits<std::uint16_t>::max()};
            id = static_cast<std::uint16_t>(distribution(random));
        } catch (...) {
            return std::unexpected(UdpQueryError{UdpQueryErrorCode::IdGeneration});
        }
        // Name/type/class validation has succeeded; fill the generated header ID.
        (*packet)[0] = static_cast<std::byte>(id >> 8);
        (*packet)[1] = static_cast<std::byte>(id & 0xFFU);
    }
    if (deadline.expired()) {
        return timeout_error({}, 0);
    }

    auto socket = net::Socket::open(server.family(), net::SocketTransport::Udp);
    if (!socket) {
        return network_error(socket.error());
    }
    const auto sent = net::send_datagram(*socket, server, *packet, deadline);
    if (!sent) {
        if (sent.error().code == net::NetworkErrorCode::TimedOut) {
            return timeout_error({}, 0);
        }
        return network_error(sent.error());
    }

    UdpQueryErrorDetail last_rejection;
    std::size_t ignored = 0;
    for (;;) {
        if (deadline.expired()) {
            return timeout_error(last_rejection, ignored);
        }
        auto received = net::receive_datagram(*socket, deadline);
        if (!received) {
            if (received.error().code == net::NetworkErrorCode::TimedOut) {
                return timeout_error(last_rejection, ignored);
            }
            return network_error(received.error(), ignored);
        }
        if (received->sender != server) {
            ++ignored;
            continue;
        }

        auto response = dns::parse_message(received->bytes);
        if (!response) {
            last_rejection = response.error();
            ++ignored;
            continue;
        }
        const auto matched = validate_response(*response, question, id);
        if (!matched) {
            last_rejection = matched.error();
            ++ignored;
            continue;
        }

        const auto finished_at = net::Deadline::Clock::now();
        if (deadline.expired(finished_at)) {
            return timeout_error(last_rejection, ignored);
        }
        return UdpQueryResult{
            server, question, id, std::move(*response),
            std::chrono::duration_cast<std::chrono::microseconds>(finished_at - started_at),
            ignored};
    }
}

} // namespace dnslab::app
