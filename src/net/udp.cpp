#include "net/udp.hpp"
#include "net/native_socket.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#if !defined(_WIN32)
#include <sys/uio.h>
#endif

namespace dnslab::net {
namespace {

constexpr std::size_t datagram_capacity = 65535;

} // 命名空间

using detail::AddressLength;
using detail::NativeSocket;
using detail::from_native;
using detail::interrupted;
using detail::invalid_argument;
using detail::last_error;
using detail::timed_out;
using detail::to_native;
using detail::would_block;

/// 使用平台等待接口监视指定方向，所有重试共享原截止时间。
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
        FD_SET(handle, &ready); // Winsock 将句柄存入数组，不以句柄值索引位图。
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
            continue; // 等待时长被截短或提前到期时，重新计算原预算的剩余时间。
        }
#if !defined(_WIN32)
        if ((descriptor.revents & POLLNVAL) != 0) {
            return std::unexpected(NetworkError{operation, EBADF});
        }
        if ((descriptor.revents & (descriptor.events | POLLERR | POLLHUP)) == 0) {
            continue;
        }
#endif
        // 就绪也可能表示挂起的套接字错误，由下一次读写返回具体原因。
        return {};
    }
}

/// 绑定指定本地端点，并立即保存系统调用失败时的错误码。
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

/// 查询实际本地地址，并将原生结构转换为可移植端点。
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

/// 在固定预算内原子发送一个 UDP 数据报，部分发送视为错误。
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

/// 在固定预算内接收完整 UDP 数据报，并检查两平台的截断标志。
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
            // 零字节 UDP 数据报合法，不能按 TCP 的连接关闭语义处理。
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

} // 命名空间 dnslab::net
