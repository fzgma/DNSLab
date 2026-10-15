#pragma once

#include "net/deadline.hpp"
#include "net/endpoint.hpp"
#include "net/errors.hpp"
#include "net/socket.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <vector>

namespace dnslab::net {

enum class WaitInterest { Read, Write };

struct Datagram {
    std::vector<std::byte> bytes;
    Endpoint sender;
};

[[nodiscard]] std::expected<void, NetworkError>
wait_socket(const Socket& socket, WaitInterest interest, const Deadline& deadline);

// Port zero requests an ephemeral local port; no address discovery is performed.
[[nodiscard]] std::expected<void, NetworkError>
bind_socket(const Socket& socket, const Endpoint& endpoint);

[[nodiscard]] std::expected<Endpoint, NetworkError>
local_endpoint(const Socket& socket);

// The caller supplies a UDP socket. Datagrams are neither split nor connected.
[[nodiscard]] std::expected<void, NetworkError>
send_datagram(const Socket& socket, const Endpoint& destination,
              std::span<const std::byte> bytes, const Deadline& deadline);

// Returns the full datagram and source endpoint; a truncated prefix is an error.
[[nodiscard]] std::expected<Datagram, NetworkError>
receive_datagram(const Socket& socket, const Deadline& deadline);

} // namespace dnslab::net
