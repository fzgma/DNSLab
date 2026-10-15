#include "net/socket.hpp"

#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#else
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace dnslab::net {
namespace {

#if defined(_WIN32)

// 每个成功创建的套接字接管一次初始化引用，避免依赖全局对象的析构顺序。
// 即使全局空套接字稍后才获得句柄，引用也会随句柄一起转移。
class WinsockRegistration {
public:
    /// 初始化 Winsock 2.2，并记录初始化或版本协商错误。
    WinsockRegistration() noexcept {
        WSADATA data{};
        constexpr WORD version = MAKEWORD(2, 2);
        error_ = ::WSAStartup(version, &data);
        if (error_ != 0) {
            return;
        }
        active_ = true;
        if (data.wVersion != version) {
            (void)::WSACleanup();
            active_ = false;
            error_ = WSAVERNOTSUPPORTED;
        }
    }

    /// 清理尚未转交给套接字的 Winsock 初始化引用。
    ~WinsockRegistration() noexcept {
        if (active_) {
            (void)::WSACleanup();
        }
    }

    /// 禁止复制初始化引用，确保只清理一次。
    WinsockRegistration(const WinsockRegistration&) = delete;
    /// 禁止赋值复制引用所有权。
    WinsockRegistration& operator=(const WinsockRegistration&) = delete;

    /// 返回初始化阶段保存的原生错误码。
    [[nodiscard]] int error() const noexcept {
        return error_;
    }

    /// 将初始化引用交给新套接字，解除临时对象的清理责任。
    void transfer_to_socket() noexcept {
        active_ = false;
    }

private:
    int error_{};
    bool active_{};
};

constexpr int unsupported_family = WSAEAFNOSUPPORT;
constexpr int unsupported_transport = WSAESOCKTNOSUPPORT;

#else

constexpr int unsupported_family = EAFNOSUPPORT;
constexpr int unsupported_transport = ESOCKTNOSUPPORT;

#endif

} // 命名空间

/// 在对象析构时统一释放系统资源。
Socket::~Socket() noexcept {
    close();
}

/// 移动句柄及其初始化引用，并立即清空来源对象。
Socket::Socket(Socket&& other) noexcept
    : handle_(std::exchange(other.handle_, invalid_handle)) {}

/// 在排除自移动后释放旧资源并接管新句柄。
Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = std::exchange(other.handle_, invalid_handle);
    }
    return *this;
}

/// 将句柄置空后执行平台关闭操作，确保重复调用安全。
void Socket::close() noexcept {
    if (!valid()) {
        return;
    }
    const auto handle = std::exchange(handle_, invalid_handle);
#if defined(_WIN32)
    (void)::closesocket(static_cast<SOCKET>(handle));
    (void)::WSACleanup();
#else
    // Linux 即使返回 EINTR 也已释放描述符，重试可能误关被复用的描述符。
    (void)::close(handle);
#endif
}

/// 校验地址族与传输类型，创建非阻塞句柄并在失败时自动清理。
std::expected<Socket, NetworkError>
Socket::open(IpFamily family, SocketTransport transport) {
    int address_family{};
    switch (family) {
    case IpFamily::V4:
        address_family = AF_INET;
        break;
    case IpFamily::V6:
        address_family = AF_INET6;
        break;
    default:
        return std::unexpected(NetworkError{
            NetworkOperation::SocketCreate, unsupported_family});
    }

    int socket_type{};
    int protocol{};
    switch (transport) {
    case SocketTransport::Udp:
        socket_type = SOCK_DGRAM;
        protocol = IPPROTO_UDP;
        break;
    case SocketTransport::Tcp:
        socket_type = SOCK_STREAM;
        protocol = IPPROTO_TCP;
        break;
    default:
        return std::unexpected(NetworkError{
            NetworkOperation::SocketCreate, unsupported_transport});
    }

#if defined(_WIN32)
    WinsockRegistration registration;
    if (registration.error() != 0) {
        return std::unexpected(NetworkError{
            NetworkOperation::Startup, registration.error()});
    }

    const auto handle = ::WSASocketW(address_family, socket_type, protocol,
                                     nullptr, 0,
                                     WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (handle == INVALID_SOCKET) {
        const int error = ::WSAGetLastError();
        return std::unexpected(NetworkError{NetworkOperation::SocketCreate, error});
    }

    Socket result{static_cast<native_handle_type>(handle)};
    registration.transfer_to_socket();
    u_long nonblocking = 1;
    if (::ioctlsocket(handle, static_cast<long>(FIONBIO), &nonblocking) == SOCKET_ERROR) {
        const int error = ::WSAGetLastError();
        return std::unexpected(NetworkError{NetworkOperation::SetNonBlocking, error});
    }
#else
    const int handle = ::socket(address_family,
                                socket_type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
    if (handle == -1) {
        const int error = errno;
        return std::unexpected(NetworkError{NetworkOperation::SocketCreate, error});
    }
    Socket result{handle};
#endif
    return result;
}

} // 命名空间 dnslab::net
