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

// The caller supplies a fresh nonblocking TCP socket and owns its lifetime.
// Discard the connection after a failed connect or incomplete stream operation.
[[nodiscard]] std::expected<void, NetworkError>
connect_socket(Socket& socket, const Endpoint& destination, const Deadline& deadline);

// Empty buffers succeed while the socket is valid and the deadline is live.
// Partial progress does not renew the deadline or turn EOF into success.
[[nodiscard]] std::expected<void, NetworkError>
send_all(Socket& socket, std::span<const std::byte> bytes, const Deadline& deadline);

[[nodiscard]] std::expected<void, NetworkError>
receive_exact(Socket& socket, std::span<std::byte> bytes, const Deadline& deadline);

// Two-byte network-order length framing; payloads must contain 12..65535 bytes.
// These functions do not interpret DNS fields or consume the following frame.
[[nodiscard]] std::expected<void, NetworkError>
send_tcp_message(Socket& socket, std::span<const std::byte> bytes, const Deadline& deadline);

[[nodiscard]] std::expected<std::vector<std::byte>, NetworkError>
receive_tcp_message(Socket& socket, const Deadline& deadline);

} // namespace dnslab::net
