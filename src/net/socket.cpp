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

// Each successful Socket takes one registration. This also works for a default
// global Socket that receives a handle later, independent of static destruction order.
class WinsockRegistration {
public:
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

    ~WinsockRegistration() noexcept {
        if (active_) {
            (void)::WSACleanup();
        }
    }

    WinsockRegistration(const WinsockRegistration&) = delete;
    WinsockRegistration& operator=(const WinsockRegistration&) = delete;

    [[nodiscard]] int error() const noexcept {
        return error_;
    }

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

} // namespace

Socket::~Socket() noexcept {
    close();
}

Socket::Socket(Socket&& other) noexcept
    : handle_(std::exchange(other.handle_, invalid_handle)) {}

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = std::exchange(other.handle_, invalid_handle);
    }
    return *this;
}

void Socket::close() noexcept {
    if (!valid()) {
        return;
    }
    const auto handle = std::exchange(handle_, invalid_handle);
#if defined(_WIN32)
    (void)::closesocket(static_cast<SOCKET>(handle));
    (void)::WSACleanup();
#else
    // Linux releases the descriptor even on EINTR; retrying could close a reused fd.
    (void)::close(handle);
#endif
}

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

} // namespace dnslab::net
