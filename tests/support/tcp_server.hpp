#pragma once

#include "dns/types.hpp"
#include "net/deadline.hpp"
#include "net/socket.hpp"
#include "net/udp.hpp"

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace dnslab::test {

class FixtureError : public std::runtime_error {
public:
    explicit FixtureError(const std::string& operation, int error = 0,
                          bool timeout = false)
        : std::runtime_error(operation + " (native error " +
                             std::to_string(error) + ")"),
          system_code(error), timed_out(timeout) {}
    int system_code;
    bool timed_out;
};

namespace tcp_fixture_detail {

using Handle = net::Socket::native_handle_type;
inline constexpr Handle invalid_handle = static_cast<Handle>(-1);

inline int last_error() noexcept {
#if defined(_WIN32)
    return ::WSAGetLastError();
#else
    return errno;
#endif
}

inline bool interrupted(int error) noexcept {
#if defined(_WIN32)
    return error == WSAEINTR;
#else
    return error == EINTR;
#endif
}

inline bool would_block(int error) noexcept {
#if defined(_WIN32)
    return error == WSAEWOULDBLOCK;
#else
    return error == EAGAIN || error == EWOULDBLOCK;
#endif
}

inline bool wait(Handle handle, bool read, const net::Deadline& deadline) {
    for (;;) {
        if (deadline.expired()) {
            return false;
        }
        const auto milliseconds = std::min<std::int64_t>(
            deadline.remaining().count(), INT_MAX);
#if defined(_WIN32)
        fd_set selected{};
        FD_ZERO(&selected);
        FD_SET(static_cast<SOCKET>(handle), &selected);
        timeval timeout{};
        timeout.tv_sec = static_cast<long>(milliseconds / 1000);
        timeout.tv_usec = static_cast<long>((milliseconds % 1000) * 1000);
        const int result = ::select(0, read ? &selected : nullptr,
                                    read ? nullptr : &selected, nullptr, &timeout);
#else
        pollfd selected{handle, static_cast<short>(read ? POLLIN : POLLOUT), 0};
        const int result = ::poll(&selected, 1, static_cast<int>(milliseconds));
#endif
        if (result > 0) {
            return !deadline.expired();
        }
        if (result == 0) {
            continue;
        }
        const int error = last_error();
        if (!interrupted(error)) {
            throw FixtureError("wait", error);
        }
    }
}

inline void require_time(const net::Deadline& deadline) {
    if (deadline.expired()) {
        throw FixtureError("deadline expired", 0, true);
    }
}

inline net::Endpoint loopback(net::IpFamily family, std::uint16_t port) {
    net::Endpoint endpoint{};
    endpoint.port = port;
    if (family == net::IpFamily::V4) {
        endpoint.address = net::Ipv4Address{
            std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1}};
    } else {
        net::Ipv6Address address{};
        address.back() = std::byte{1};
        endpoint.address = address;
    }
    return endpoint;
}

} // namespace tcp_fixture_detail

class TcpStream {
public:
    using native_handle_type = net::Socket::native_handle_type;

    explicit TcpStream(native_handle_type accepted) : handle_(accepted) {
        try {
#if defined(_WIN32)
            WSADATA data{};
            const int startup = ::WSAStartup(MAKEWORD(2, 2), &data);
            if (startup != 0) {
                throw FixtureError("accepted stream startup", startup);
            }
            owns_startup_ = true;
            u_long enabled = 1;
            if (::ioctlsocket(static_cast<SOCKET>(handle_),
                              static_cast<long>(FIONBIO), &enabled) != 0) {
                throw FixtureError("accepted stream nonblocking",
                                   tcp_fixture_detail::last_error());
            }
#else
            const int flags = ::fcntl(handle_, F_GETFL, 0);
            const int descriptor_flags = ::fcntl(handle_, F_GETFD, 0);
            if (flags == -1 || descriptor_flags == -1 ||
                ::fcntl(handle_, F_SETFL, flags | O_NONBLOCK) == -1 ||
                ::fcntl(handle_, F_SETFD, descriptor_flags | FD_CLOEXEC) == -1) {
                throw FixtureError("accepted stream nonblocking", errno);
            }
#endif
        } catch (...) {
            close();
            throw;
        }
    }

    ~TcpStream() { close(); }
    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;
    TcpStream(TcpStream&& other) noexcept
        : handle_(std::exchange(other.handle_, tcp_fixture_detail::invalid_handle))
#if defined(_WIN32)
        , owns_startup_(std::exchange(other.owns_startup_, false))
#endif
    {}
    TcpStream& operator=(TcpStream&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = std::exchange(other.handle_, tcp_fixture_detail::invalid_handle);
#if defined(_WIN32)
            owns_startup_ = std::exchange(other.owns_startup_, false);
#endif
        }
        return *this;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != tcp_fixture_detail::invalid_handle;
    }
    [[nodiscard]] native_handle_type native_handle() const noexcept { return handle_; }

    void close() noexcept {
        if (valid()) {
#if defined(_WIN32)
            ::closesocket(static_cast<SOCKET>(handle_));
#else
            ::close(handle_);
#endif
            handle_ = tcp_fixture_detail::invalid_handle;
        }
#if defined(_WIN32)
        if (owns_startup_) {
            ::WSACleanup();
            owns_startup_ = false;
        }
#endif
    }

    void shutdown_write() {
#if defined(_WIN32)
        const int result = ::shutdown(static_cast<SOCKET>(handle_), SD_SEND);
#else
        const int result = ::shutdown(handle_, SHUT_WR);
#endif
        if (result != 0) {
            throw FixtureError("shutdown", tcp_fixture_detail::last_error());
        }
    }

    void reset() {
        linger value{};
        value.l_onoff = 1;
        value.l_linger = 0;
#if defined(_WIN32)
        const int result = ::setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET,
                                       SO_LINGER, reinterpret_cast<const char*>(&value),
                                       static_cast<int>(sizeof(value)));
#else
        const int result = ::setsockopt(handle_, SOL_SOCKET, SO_LINGER, &value,
                                       static_cast<socklen_t>(sizeof(value)));
#endif
        if (result != 0) {
            throw FixtureError("reset", tcp_fixture_detail::last_error());
        }
        close();
    }

    void send_all(std::span<const std::byte> bytes, const net::Deadline& deadline) {
        std::size_t sent = 0;
        while (sent < bytes.size()) {
            tcp_fixture_detail::require_time(deadline);
            const auto length = std::min(bytes.size() - sent,
                                         static_cast<std::size_t>(INT_MAX));
#if defined(_WIN32)
            const auto count = ::send(static_cast<SOCKET>(handle_),
                reinterpret_cast<const char*>(bytes.data() + sent),
                static_cast<int>(length), 0);
#else
            const auto count = ::send(handle_, bytes.data() + sent, length, MSG_NOSIGNAL);
#endif
            if (count > 0) {
                sent += static_cast<std::size_t>(count);
                continue;
            }
            const int error = tcp_fixture_detail::last_error();
            if (count < 0 && tcp_fixture_detail::interrupted(error)) {
                continue;
            }
            if (count < 0 && tcp_fixture_detail::would_block(error)) {
                if (tcp_fixture_detail::wait(handle_, false, deadline)) {
                    continue;
                }
                throw FixtureError("send timeout", 0, true);
            }
            throw FixtureError("send", error);
        }
    }

    [[nodiscard]] dns::Packet receive_exact(std::size_t size,
                                           const net::Deadline& deadline) {
        dns::Packet bytes(size);
        std::size_t received = 0;
        while (received < size) {
            tcp_fixture_detail::require_time(deadline);
            const auto length = std::min(size - received,
                                         static_cast<std::size_t>(INT_MAX));
#if defined(_WIN32)
            const auto count = ::recv(static_cast<SOCKET>(handle_),
                reinterpret_cast<char*>(bytes.data() + received),
                static_cast<int>(length), 0);
#else
            const auto count = ::recv(handle_, bytes.data() + received, length, 0);
#endif
            if (count > 0) {
                received += static_cast<std::size_t>(count);
                continue;
            }
            if (count == 0) {
                throw FixtureError("receive EOF");
            }
            const int error = tcp_fixture_detail::last_error();
            if (tcp_fixture_detail::interrupted(error)) {
                continue;
            }
            if (tcp_fixture_detail::would_block(error)) {
                if (tcp_fixture_detail::wait(handle_, true, deadline)) {
                    continue;
                }
                throw FixtureError("receive timeout", 0, true);
            }
            throw FixtureError("receive", error);
        }
        return bytes;
    }

    void send_frame(std::span<const std::byte> bytes, const net::Deadline& deadline) {
        if (bytes.size() > 65535) {
            throw std::invalid_argument("test TCP frame exceeds 65535 bytes");
        }
        const std::byte prefix[]{static_cast<std::byte>(bytes.size() >> 8),
                                 static_cast<std::byte>(bytes.size() & 0xffU)};
        send_all(prefix, deadline);
        send_all(bytes, deadline);
    }

    [[nodiscard]] dns::Packet receive_frame(const net::Deadline& deadline) {
        const auto prefix = receive_exact(2, deadline);
        const auto size = (std::to_integer<std::size_t>(prefix[0]) << 8) |
                          std::to_integer<std::size_t>(prefix[1]);
        return receive_exact(size, deadline);
    }

private:
    native_handle_type handle_{tcp_fixture_detail::invalid_handle};
#if defined(_WIN32)
    bool owns_startup_{};
#endif
};

class TcpServer {
public:
    explicit TcpServer(net::IpFamily family = net::IpFamily::V4,
                       std::uint16_t port = 0) {
        auto socket = net::Socket::open(family, net::SocketTransport::Tcp);
        if (!socket) {
            throw FixtureError("listener socket", socket.error().system_code);
        }
        socket_ = std::move(*socket);
        const auto bound = net::bind_socket(socket_,
            tcp_fixture_detail::loopback(family, port));
        if (!bound) {
            throw FixtureError("listener bind", bound.error().system_code);
        }
        const auto local = net::local_endpoint(socket_);
        if (!local) {
            throw FixtureError("listener endpoint", local.error().system_code);
        }
        endpoint_ = *local;
#if defined(_WIN32)
        const int result = ::listen(static_cast<SOCKET>(socket_.native_handle()), 8);
#else
        const int result = ::listen(socket_.native_handle(), 8);
#endif
        if (result != 0) {
            throw FixtureError("listen", tcp_fixture_detail::last_error());
        }
    }

    [[nodiscard]] const net::Endpoint& endpoint() const noexcept { return endpoint_; }
    void close() noexcept { socket_.close(); }

    [[nodiscard]] bool pending(const net::Deadline& deadline) const {
        return tcp_fixture_detail::wait(socket_.native_handle(), true, deadline);
    }

    [[nodiscard]] TcpStream accept(const net::Deadline& deadline) const {
        for (;;) {
            tcp_fixture_detail::require_time(deadline);
#if defined(_WIN32)
            const auto accepted = ::accept(static_cast<SOCKET>(socket_.native_handle()),
                                            nullptr, nullptr);
            const bool valid = accepted != INVALID_SOCKET;
#else
            const auto accepted = ::accept(socket_.native_handle(), nullptr, nullptr);
            const bool valid = accepted >= 0;
#endif
            if (valid) {
                return TcpStream{static_cast<net::Socket::native_handle_type>(accepted)};
            }
            const int error = tcp_fixture_detail::last_error();
            if (tcp_fixture_detail::interrupted(error)) {
                continue;
            }
            if (tcp_fixture_detail::would_block(error)) {
                if (pending(deadline)) {
                    continue;
                }
                throw FixtureError("accept timeout", 0, true);
            }
            throw FixtureError("accept", error);
        }
    }

private:
    net::Socket socket_;
    net::Endpoint endpoint_{};
};

} // namespace dnslab::test
