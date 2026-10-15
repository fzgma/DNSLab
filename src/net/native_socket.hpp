#pragma once

// UDP 与 TCP 共用的私有平台适配，避免系统头进入公共接口。
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

/// 立即读取当前线程的 Winsock 错误码，供清理资源前保存。
inline int last_error() noexcept { return ::WSAGetLastError(); }
/// 判断 Winsock 操作是否被中断。
inline bool interrupted(int error) noexcept { return error == WSAEINTR; }
/// 判断非阻塞 Winsock 操作是否需要等待套接字就绪。
inline bool would_block(int error) noexcept { return error == WSAEWOULDBLOCK; }
#else
using NativeSocket = int;
using AddressLength = socklen_t;

/// 立即读取当前线程的 errno，供后续调用前保存。
inline int last_error() noexcept { return errno; }
/// 判断系统调用是否因信号而中断。
inline bool interrupted(int error) noexcept { return error == EINTR; }
/// 识别 Linux 非阻塞读写的两种暂不可用错误码。
inline bool would_block(int error) noexcept { return error == EAGAIN || error == EWOULDBLOCK; }
#endif

/// 为指定操作构造不含系统错误码的参数错误。
inline NetworkError invalid_argument(NetworkOperation operation) noexcept {
    return {operation, 0, NetworkErrorCode::InvalidArgument};
}

/// 为指定操作构造预算耗尽错误。
inline NetworkError timed_out(NetworkOperation operation) noexcept {
    return {operation, 0, NetworkErrorCode::TimedOut};
}

struct NativeAddress {
    sockaddr_storage storage{};
    AddressLength length{};
};

/// 将端点地址和端口转换为对应平台的 sockaddr 存储。
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

/// 在校验地址族与结构长度后，将系统地址还原为端点。
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

} // 命名空间 dnslab::net::detail
