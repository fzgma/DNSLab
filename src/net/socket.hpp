#pragma once

#include "net/endpoint.hpp"
#include "net/errors.hpp"

#include <cstdint>
#include <expected>

namespace dnslab::net {

enum class SocketTransport { Udp, Tcp };

class Socket {
public:
#if defined(_WIN32)
    using native_handle_type = std::uintptr_t;
#else
    using native_handle_type = int;
#endif

    Socket() noexcept = default;
    ~Socket() noexcept;

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != invalid_handle;
    }

    // Borrowed handle: callers must not close it or transfer its ownership.
    [[nodiscard]] native_handle_type native_handle() const noexcept {
        return handle_;
    }

    void close() noexcept;

    // Creates a nonblocking socket without binding or connecting. Windows handles
    // are non-inheritable; Linux descriptors close on exec (fork still inherits).
    [[nodiscard]] static std::expected<Socket, NetworkError>
    open(IpFamily family, SocketTransport transport);

private:
    static constexpr native_handle_type invalid_handle =
        static_cast<native_handle_type>(-1);

    explicit Socket(native_handle_type handle) noexcept : handle_(handle) {}

    // On Windows a valid handle also owns one successful WSAStartup reference.
    native_handle_type handle_{invalid_handle};
};

} // namespace dnslab::net
