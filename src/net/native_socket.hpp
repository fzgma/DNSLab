#pragma once

// Private platform adaptation shared by UDP and TCP; public headers stay portable.
#include "net/endpoint.hpp"
#include "net/errors.hpp"

#include <cstring>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <cerrno>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#endif

namespace dnslab::net::detail {

#if defined(_WIN32)
using NativeSocket = SOCKET;
using AddressLength = int;

inline int last_error() noexcept { return ::WSAGetLastError(); }
inline bool interrupted(int error) noexcept { return error == WSAEINTR; }
inline bool would_block(int error) noexcept { return error == WSAEWOULDBLOCK; }
#else
using NativeSocket = int;
using AddressLength = socklen_t;

inline int last_error() noexcept { return errno; }
inline bool interrupted(int error) noexcept { return error == EINTR; }
inline bool would_block(int error) noexcept { return error == EAGAIN || error == EWOULDBLOCK; }
#endif

inline NetworkError invalid_argument(NetworkOperation operation) noexcept {
    return {operation, 0, NetworkErrorCode::InvalidArgument};
}

inline NetworkError timed_out(NetworkOperation operation) noexcept {
    return {operation, 0, NetworkErrorCode::TimedOut};
}

struct NativeAddress {
    sockaddr_storage storage{};
    AddressLength length{};
};

inline NativeAddress to_native(const Endpoint& endpoint) noexcept {
    NativeAddress result;
    if (const auto* bytes = std::get_if<Ipv4Address>(&endpoint.address)) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(endpoint.port);
        static_assert(sizeof(address.sin_addr) == sizeof(*bytes));
        std::memcpy(&address.sin_addr, bytes->data(), bytes->size());
        std::memcpy(&result.storage, &address, sizeof(address));
        result.length = static_cast<AddressLength>(sizeof(address));
    } else {
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(endpoint.port);
        const auto& bytes6 = std::get<Ipv6Address>(endpoint.address);
        static_assert(sizeof(address.sin6_addr) == sizeof(bytes6));
        std::memcpy(&address.sin6_addr, bytes6.data(), bytes6.size());
        std::memcpy(&result.storage, &address, sizeof(address));
        result.length = static_cast<AddressLength>(sizeof(address));
    }
    return result;
}

inline std::expected<Endpoint, NetworkError>
from_native(const sockaddr_storage& storage, AddressLength length,
            NetworkOperation operation) {
    if (storage.ss_family == AF_INET &&
        length >= static_cast<AddressLength>(sizeof(sockaddr_in))) {
        sockaddr_in address{};
        std::memcpy(&address, &storage, sizeof(address));
        Ipv4Address bytes{};
        std::memcpy(bytes.data(), &address.sin_addr, bytes.size());
        return Endpoint{bytes, ntohs(address.sin_port)};
    }
    if (storage.ss_family == AF_INET6 &&
        length >= static_cast<AddressLength>(sizeof(sockaddr_in6))) {
        sockaddr_in6 address{};
        std::memcpy(&address, &storage, sizeof(address));
        Ipv6Address bytes{};
        std::memcpy(bytes.data(), &address.sin6_addr, bytes.size());
        return Endpoint{bytes, ntohs(address.sin6_port)};
    }
    return std::unexpected(invalid_argument(operation));
}

} // namespace dnslab::net::detail
