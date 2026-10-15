#include "net/udp.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

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
#include <sys/uio.h>
#endif

namespace dnslab::net {
namespace {

constexpr std::size_t datagram_capacity = 65535;

#if defined(_WIN32)
using NativeSocket = SOCKET;
using AddressLength = int;

int last_error() noexcept { return ::WSAGetLastError(); }
bool interrupted(int error) noexcept { return error == WSAEINTR; }
bool would_block(int error) noexcept { return error == WSAEWOULDBLOCK; }
#else
using NativeSocket = int;
using AddressLength = socklen_t;

int last_error() noexcept { return errno; }
bool interrupted(int error) noexcept { return error == EINTR; }
bool would_block(int error) noexcept { return error == EAGAIN || error == EWOULDBLOCK; }
#endif

NetworkError invalid_argument(NetworkOperation operation) noexcept {
    return {operation, 0, NetworkErrorCode::InvalidArgument};
}

NetworkError timed_out(NetworkOperation operation) noexcept {
    return {operation, 0, NetworkErrorCode::TimedOut};
}

struct NativeAddress {
    sockaddr_storage storage{};
    AddressLength length{};
};

NativeAddress to_native(const Endpoint& endpoint) noexcept {
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

std::expected<Endpoint, NetworkError>
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

} // namespace

std::expected<void, NetworkError>
wait_socket(const Socket& socket, WaitInterest interest, const Deadline& deadline) {
    NetworkOperation operation;
    switch (interest) {
    case WaitInterest::Read:
        operation = NetworkOperation::WaitRead;
        break;
    case WaitInterest::Write:
        operation = NetworkOperation::WaitWrite;
        break;
    default:
        return std::unexpected(invalid_argument(NetworkOperation::WaitRead));
    }
    if (!socket.valid()) {
        return std::unexpected(invalid_argument(operation));
    }
    const auto handle = static_cast<NativeSocket>(socket.native_handle());
    for (;;) {
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
        const auto remaining = deadline.remaining().count();
        if (remaining == 0) {
            return std::unexpected(timed_out(operation));
        }
        const int milliseconds = static_cast<int>(std::min(
            remaining, static_cast<std::chrono::milliseconds::rep>(
                           (std::numeric_limits<int>::max)())));

#if defined(_WIN32)
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(handle, &ready); // Winsock stores handles in an array, not a bitmap.
        timeval timeout{};
        timeout.tv_sec = milliseconds / 1000;
        timeout.tv_usec = (milliseconds % 1000) * 1000;
        const int result = ::select(0, interest == WaitInterest::Read ? &ready : nullptr,
                                     interest == WaitInterest::Write ? &ready : nullptr,
                                     nullptr, &timeout);
#else
        pollfd descriptor{};
        descriptor.fd = handle;
        descriptor.events = static_cast<short>(interest == WaitInterest::Read ? POLLIN : POLLOUT);
        const int result = ::poll(&descriptor, 1, milliseconds);
#endif
        const int error = result < 0 ? last_error() : 0;
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
        if (result < 0) {
            if (interrupted(error)) {
                continue;
            }
            return std::unexpected(NetworkError{operation, error});
        }
        if (result == 0) {
            continue; // Recompute the same budget after a clamped or early timeout.
        }
#if !defined(_WIN32)
        if ((descriptor.revents & POLLNVAL) != 0) {
            return std::unexpected(NetworkError{operation, EBADF});
        }
        if ((descriptor.revents & (descriptor.events | POLLERR | POLLHUP)) == 0) {
            continue;
        }
#endif
        // Readiness may also signal a pending socket error; the next I/O reports it.
        return {};
    }
}

std::expected<void, NetworkError>
bind_socket(const Socket& socket, const Endpoint& endpoint) {
    if (!socket.valid()) {
        return std::unexpected(invalid_argument(NetworkOperation::Bind));
    }
    const auto address = to_native(endpoint);
    const int result = ::bind(static_cast<NativeSocket>(socket.native_handle()),
                              reinterpret_cast<const sockaddr*>(&address.storage),
                              address.length);
    if (result != 0) {
        const int error = last_error();
        return std::unexpected(NetworkError{NetworkOperation::Bind, error});
    }
    return {};
}

std::expected<Endpoint, NetworkError> local_endpoint(const Socket& socket) {
    if (!socket.valid()) {
        return std::unexpected(invalid_argument(NetworkOperation::LocalEndpoint));
    }
    sockaddr_storage address{};
    auto length = static_cast<AddressLength>(sizeof(address));
    const int result = ::getsockname(static_cast<NativeSocket>(socket.native_handle()),
                                     reinterpret_cast<sockaddr*>(&address), &length);
    if (result != 0) {
        const int error = last_error();
        return std::unexpected(NetworkError{NetworkOperation::LocalEndpoint, error});
    }
    return from_native(address, length, NetworkOperation::LocalEndpoint);
}

std::expected<void, NetworkError>
send_datagram(const Socket& socket, const Endpoint& destination,
              std::span<const std::byte> bytes, const Deadline& deadline) {
    constexpr auto operation = NetworkOperation::Send;
    if (!socket.valid() || destination.port == 0 || bytes.size() > datagram_capacity) {
        return std::unexpected(invalid_argument(operation));
    }
    const auto address = to_native(destination);
    const auto handle = static_cast<NativeSocket>(socket.native_handle());
    const char empty_buffer{};
    const auto* data = bytes.empty() ? &empty_buffer : reinterpret_cast<const char*>(bytes.data());
    for (;;) {
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
#if defined(_WIN32)
        const auto sent = ::sendto(handle, data, static_cast<int>(bytes.size()), 0,
                                   reinterpret_cast<const sockaddr*>(&address.storage),
                                   address.length);
#else
        const auto sent = ::sendto(handle, data, bytes.size(), 0,
                                   reinterpret_cast<const sockaddr*>(&address.storage),
                                   address.length);
#endif
        const int error = sent < 0 ? last_error() : 0;
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
        if (sent >= 0) {
            if (static_cast<std::size_t>(sent) != bytes.size()) {
                return std::unexpected(NetworkError{
                    operation, 0, NetworkErrorCode::IncompleteDatagram});
            }
            return {};
        }
        if (interrupted(error)) {
            continue;
        }
        if (would_block(error)) {
            const auto ready = wait_socket(socket, WaitInterest::Write, deadline);
            if (!ready) {
                return std::unexpected(ready.error());
            }
            continue;
        }
        return std::unexpected(NetworkError{operation, error});
    }
}

std::expected<Datagram, NetworkError>
receive_datagram(const Socket& socket, const Deadline& deadline) {
    constexpr auto operation = NetworkOperation::Receive;
    if (!socket.valid()) {
        return std::unexpected(invalid_argument(operation));
    }
    if (deadline.expired()) {
        return std::unexpected(timed_out(operation));
    }
    std::vector<std::byte> bytes(datagram_capacity);
    const auto handle = static_cast<NativeSocket>(socket.native_handle());
    for (;;) {
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
        sockaddr_storage sender{};
#if defined(_WIN32)
        auto sender_length = static_cast<AddressLength>(sizeof(sender));
        const auto received = ::recvfrom(handle, reinterpret_cast<char*>(bytes.data()),
                                         static_cast<int>(bytes.size()), 0,
                                         reinterpret_cast<sockaddr*>(&sender), &sender_length);
#else
        iovec buffer{bytes.data(), bytes.size()};
        msghdr message{};
        message.msg_name = &sender;
        message.msg_namelen = static_cast<socklen_t>(sizeof(sender));
        message.msg_iov = &buffer;
        message.msg_iovlen = 1;
        const auto received = ::recvmsg(handle, &message, 0);
        const auto sender_length = message.msg_namelen;
#endif
        const int error = received < 0 ? last_error() : 0;
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
#if defined(_WIN32)
        if (received < 0 && error == WSAEMSGSIZE) {
            return std::unexpected(NetworkError{
                operation, error, NetworkErrorCode::DatagramTruncated});
        }
#else
        if (received >= 0 && (message.msg_flags & MSG_TRUNC) != 0) {
            return std::unexpected(NetworkError{
                operation, 0, NetworkErrorCode::DatagramTruncated});
        }
#endif
        if (received >= 0) {
            if (static_cast<std::size_t>(received) > bytes.size()) {
                return std::unexpected(NetworkError{
                    operation, 0, NetworkErrorCode::DatagramTruncated});
            }
            auto endpoint = from_native(sender, sender_length, operation);
            if (!endpoint) {
                return std::unexpected(endpoint.error());
            }
            bytes.resize(static_cast<std::size_t>(received));
            return Datagram{std::move(bytes), std::move(*endpoint)};
        }
        if (interrupted(error)) {
            continue;
        }
        if (would_block(error)) {
            const auto ready = wait_socket(socket, WaitInterest::Read, deadline);
            if (!ready) {
                return std::unexpected(ready.error());
            }
            continue;
        }
        return std::unexpected(NetworkError{operation, error});
    }
}

} // namespace dnslab::net
