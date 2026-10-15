#include "net/tcp.hpp"
#include "net/native_socket.hpp"
#include "net/udp.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace dnslab::net {
namespace {

using detail::NativeSocket;
using detail::interrupted;
using detail::invalid_argument;
using detail::last_error;
using detail::timed_out;
using detail::would_block;

constexpr std::size_t minimum_message_size = 12;
constexpr std::size_t maximum_message_size = 65535;

/// 按平台识别表示非阻塞连接尚未完成的错误码。
bool connect_pending(int error) noexcept {
#if defined(_WIN32)
    // WSAEINPROGRESS 和 WSAEINTR 描述旧式阻塞调用，不代表此次非阻塞连接挂起；
    // 保留这些原生失败，避免误将它们转换成等待超时。
    return error == WSAEWOULDBLOCK || error == WSAEALREADY;
#else
    return error == EINPROGRESS || error == EALREADY || error == EINTR;
#endif
}

/// 等待非阻塞连接结束，并通过 SO_ERROR 确认实际成功或失败。
// Winsock 用异常集合报告连接失败，普通流的可写事件本身不能证明连接成功。
std::expected<void, NetworkError>
finish_connect(NativeSocket handle, const Deadline& deadline) {
    constexpr auto operation = NetworkOperation::Connect;
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
        fd_set writable;
        fd_set exceptional;
        FD_ZERO(&writable);
        FD_ZERO(&exceptional);
        FD_SET(handle, &writable);
        FD_SET(handle, &exceptional);
        timeval timeout{};
        timeout.tv_sec = milliseconds / 1000;
        timeout.tv_usec = (milliseconds % 1000) * 1000;
        const int result = ::select(0, nullptr, &writable, &exceptional, &timeout);
#else
        pollfd descriptor{};
        descriptor.fd = handle;
        descriptor.events = POLLOUT;
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
            continue;
        }
#if !defined(_WIN32)
        if ((descriptor.revents & POLLNVAL) != 0) {
            return std::unexpected(NetworkError{operation, EBADF});
        }
        if ((descriptor.revents & (POLLOUT | POLLERR | POLLHUP)) == 0) {
            continue;
        }
#endif
        int socket_error{};
#if defined(_WIN32)
        auto length = static_cast<int>(sizeof(socket_error));
        const int checked = ::getsockopt(handle, SOL_SOCKET, SO_ERROR,
                                         reinterpret_cast<char*>(&socket_error), &length);
#else
        auto length = static_cast<socklen_t>(sizeof(socket_error));
        const int checked = ::getsockopt(handle, SOL_SOCKET, SO_ERROR,
                                         &socket_error, &length);
#endif
        const int check_error = checked < 0 ? last_error() : 0;
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
        if (checked < 0) {
            if (interrupted(check_error)) {
                continue;
            }
            return std::unexpected(NetworkError{operation, check_error});
        }
        if (socket_error != 0) {
            return std::unexpected(NetworkError{operation, socket_error});
        }
#if defined(_WIN32)
        if (!FD_ISSET(handle, &writable)) {
            continue;
        }
#endif
        return {};
    }
}

} // 命名空间

/// 发起连接并在尚未完成时进入专用等待流程，全程共享原截止时间。
std::expected<void, NetworkError>
connect_socket(Socket& socket, const Endpoint& destination, const Deadline& deadline) {
    constexpr auto operation = NetworkOperation::Connect;
    if (!socket.valid() || destination.port == 0) {
        return std::unexpected(invalid_argument(operation));
    }
    if (deadline.expired()) {
        return std::unexpected(timed_out(operation));
    }
    const auto address = detail::to_native(destination);
    const auto handle = static_cast<NativeSocket>(socket.native_handle());
    const int result = ::connect(handle,
                                 reinterpret_cast<const sockaddr*>(&address.storage),
                                 address.length);
    const int error = result < 0 ? last_error() : 0;
    if (deadline.expired()) {
        return std::unexpected(timed_out(operation));
    }
    if (result == 0) {
        return {};
    }
    if (!connect_pending(error)) {
        return std::unexpected(NetworkError{operation, error});
    }
    return finish_connect(handle, deadline);
}

/// 循环处理部分发送和暂不可写状态，直到缓冲区发送完毕或预算耗尽。
std::expected<void, NetworkError>
send_all(Socket& socket, std::span<const std::byte> bytes, const Deadline& deadline) {
    constexpr auto operation = NetworkOperation::Send;
    if (!socket.valid()) {
        return std::unexpected(invalid_argument(operation));
    }
    if (deadline.expired()) {
        return std::unexpected(timed_out(operation));
    }
    const auto handle = static_cast<NativeSocket>(socket.native_handle());
    while (!bytes.empty()) {
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
        const auto length = std::min(bytes.size(),
                                     static_cast<std::size_t>((std::numeric_limits<int>::max)()));
#if defined(_WIN32)
        const auto sent = ::send(handle, reinterpret_cast<const char*>(bytes.data()),
                                 static_cast<int>(length), 0);
#else
        // 避免对端关闭时 SIGPIPE 终止进程，将失败交由错误返回处理。
        const auto sent = ::send(handle, bytes.data(), length, MSG_NOSIGNAL);
#endif
        const int error = sent < 0 ? last_error() : 0;
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
        if (sent > 0) {
            bytes = bytes.subspan(static_cast<std::size_t>(sent));
            continue;
        }
        if (sent == 0) {
            return std::unexpected(NetworkError{
                operation, 0, NetworkErrorCode::ConnectionClosed});
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
    return {};
}

/// 循环接收至指定长度，严格区分暂不可读与连接已关闭。
std::expected<void, NetworkError>
receive_exact(Socket& socket, std::span<std::byte> bytes, const Deadline& deadline) {
    constexpr auto operation = NetworkOperation::Receive;
    if (!socket.valid()) {
        return std::unexpected(invalid_argument(operation));
    }
    if (deadline.expired()) {
        return std::unexpected(timed_out(operation));
    }
    const auto handle = static_cast<NativeSocket>(socket.native_handle());
    while (!bytes.empty()) {
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
        const auto length = std::min(bytes.size(),
                                     static_cast<std::size_t>((std::numeric_limits<int>::max)()));
#if defined(_WIN32)
        const auto received = ::recv(handle, reinterpret_cast<char*>(bytes.data()),
                                     static_cast<int>(length), 0);
#else
        const auto received = ::recv(handle, bytes.data(), length, 0);
#endif
        const int error = received < 0 ? last_error() : 0;
        if (deadline.expired()) {
            return std::unexpected(timed_out(operation));
        }
        if (received > 0) {
            bytes = bytes.subspan(static_cast<std::size_t>(received));
            continue;
        }
        if (received == 0) {
            return std::unexpected(NetworkError{
                operation, 0, NetworkErrorCode::ConnectionClosed});
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
    return {};
}

/// 校验消息长度后依次发送长度前缀和正文，两段使用同一截止时间。
std::expected<void, NetworkError>
send_tcp_message(Socket& socket, std::span<const std::byte> bytes, const Deadline& deadline) {
    if (!socket.valid()) {
        return std::unexpected(invalid_argument(NetworkOperation::Send));
    }
    if (bytes.size() < minimum_message_size || bytes.size() > maximum_message_size) {
        return std::unexpected(NetworkError{
            NetworkOperation::Send, 0, NetworkErrorCode::InvalidMessageLength});
    }
    const std::array prefix{
        static_cast<std::byte>((bytes.size() >> 8U) & 0xffU),
        static_cast<std::byte>(bytes.size() & 0xffU),
    };
    const auto prefixed = send_all(socket, prefix, deadline);
    if (!prefixed) {
        return std::unexpected(prefixed.error());
    }
    return send_all(socket, bytes, deadline);
}

/// 先完整读取并验证前缀，再按可信长度分配和接收正文。
std::expected<std::vector<std::byte>, NetworkError>
receive_tcp_message(Socket& socket, const Deadline& deadline) {
    std::array<std::byte, 2> prefix{};
    const auto prefixed = receive_exact(socket, prefix, deadline);
    if (!prefixed) {
        return std::unexpected(prefixed.error());
    }
    const auto length = (std::to_integer<std::size_t>(prefix[0]) << 8U) |
                        std::to_integer<std::size_t>(prefix[1]);
    if (length < minimum_message_size) {
        return std::unexpected(NetworkError{
            NetworkOperation::Receive, 0, NetworkErrorCode::InvalidMessageLength});
    }
    std::vector<std::byte> bytes(length);
    const auto received = receive_exact(socket, bytes, deadline);
    if (!received) {
        return std::unexpected(received.error());
    }
    return bytes;
}

} // 命名空间 dnslab::net
