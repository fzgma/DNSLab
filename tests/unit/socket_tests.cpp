#include "net/socket.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <type_traits>
#include <utility>

namespace {

using namespace dnslab::net;

static_assert(!std::is_copy_constructible_v<Socket>);
static_assert(!std::is_copy_assignable_v<Socket>);
static_assert(std::is_nothrow_default_constructible_v<Socket>);
static_assert(std::is_nothrow_move_constructible_v<Socket>);
static_assert(std::is_nothrow_move_assignable_v<Socket>);
static_assert(std::is_nothrow_destructible_v<Socket>);

#if defined(_WIN32)
using NativeSocket = SOCKET;
using SocketLength = int;
constexpr int unsupported_family = WSAEAFNOSUPPORT;
constexpr int unsupported_transport = WSAESOCKTNOSUPPORT;
constexpr int closed_handle_error = WSAENOTSOCK;
static_assert(std::is_same_v<Socket::native_handle_type, std::uintptr_t>);
#else
using NativeSocket = int;
using SocketLength = socklen_t;
constexpr int unsupported_family = EAFNOSUPPORT;
constexpr int unsupported_transport = ESOCKTNOSUPPORT;
constexpr int closed_handle_error = EBADF;
static_assert(std::is_same_v<Socket::native_handle_type, int>);
#endif

int last_socket_error() noexcept {
#if defined(_WIN32)
    return ::WSAGetLastError();
#else
    return errno;
#endif
}

Socket open_socket(IpFamily family, SocketTransport transport) {
    auto result = Socket::open(family, transport);
    if (!result) {
        CAPTURE(static_cast<int>(family), static_cast<int>(transport),
                static_cast<int>(result.error().operation), result.error().system_code);
        if (family == IpFamily::V6 &&
            result.error().operation == NetworkOperation::SocketCreate &&
            result.error().system_code == unsupported_family) {
            SKIP("The operating system explicitly reports IPv6 is unsupported");
        }
        REQUIRE(result.has_value());
    }
    return std::move(*result);
}

int integer_option(Socket::native_handle_type handle, int option) {
    int value{};
    SocketLength length = static_cast<SocketLength>(sizeof(value));
    const int result = ::getsockopt(static_cast<NativeSocket>(handle), SOL_SOCKET,
                                    option, reinterpret_cast<char*>(&value), &length);
    const int error = result == 0 ? 0 : last_socket_error();
    CAPTURE(option, error);
    REQUIRE(result == 0);
    REQUIRE(length == static_cast<SocketLength>(sizeof(value)));
    return value;
}

// A socket opened before the close remains alive when this helper is called.
// No new socket is opened between closing a handle and checking it for invalidity.
void check_closed_handle(Socket::native_handle_type handle) {
    int value{};
    SocketLength length = static_cast<SocketLength>(sizeof(value));
    const int result = ::getsockopt(static_cast<NativeSocket>(handle), SOL_SOCKET,
                                    SO_TYPE, reinterpret_cast<char*>(&value), &length);
    const int error = last_socket_error();
    CAPTURE(error);
    REQUIRE(result == -1);
    CHECK(error == closed_handle_error);
}

void check_family_and_type(IpFamily family, SocketTransport transport) {
    auto socket = open_socket(family, transport);
    REQUIRE(socket.valid());
    const int expected_family = family == IpFamily::V4 ? AF_INET : AF_INET6;
    const int expected_type = transport == SocketTransport::Udp ? SOCK_DGRAM : SOCK_STREAM;
    const int expected_protocol = transport == SocketTransport::Udp ? IPPROTO_UDP : IPPROTO_TCP;
    CHECK(integer_option(socket.native_handle(), SO_TYPE) == expected_type);

#if defined(_WIN32)
    WSAPROTOCOL_INFOW protocol_info{};
    int length = static_cast<int>(sizeof(protocol_info));
    const int result = ::getsockopt(static_cast<SOCKET>(socket.native_handle()),
                                    SOL_SOCKET, SO_PROTOCOL_INFOW,
                                    reinterpret_cast<char*>(&protocol_info), &length);
    const int error = result == 0 ? 0 : ::WSAGetLastError();
    CAPTURE(error);
    REQUIRE(result == 0);
    CHECK(protocol_info.iAddressFamily == expected_family);
    CHECK(protocol_info.iSocketType == expected_type);
    CHECK(protocol_info.iProtocol == expected_protocol);

    DWORD handle_flags{};
    const auto handle_result = ::GetHandleInformation(
        reinterpret_cast<HANDLE>(socket.native_handle()), &handle_flags);
    const auto handle_error = handle_result != 0 ? DWORD{0} : ::GetLastError();
    CAPTURE(handle_error);
    REQUIRE(handle_result != 0);
    CHECK((handle_flags & HANDLE_FLAG_INHERIT) == 0);
#else
    CHECK(integer_option(socket.native_handle(), SO_DOMAIN) == expected_family);
    CHECK(integer_option(socket.native_handle(), SO_PROTOCOL) == expected_protocol);

    const int descriptor_flags = ::fcntl(socket.native_handle(), F_GETFD);
    const int descriptor_error = descriptor_flags == -1 ? errno : 0;
    CAPTURE(descriptor_error);
    REQUIRE(descriptor_flags != -1);
    CHECK((descriptor_flags & FD_CLOEXEC) != 0);

    const int status_flags = ::fcntl(socket.native_handle(), F_GETFL);
    const int status_error = status_flags == -1 ? errno : 0;
    CAPTURE(status_error);
    REQUIRE(status_flags != -1);
    CHECK((status_flags & O_NONBLOCK) != 0);
#endif
}

TEST_CASE("A default socket is invalid and can be closed repeatedly", "[socket]") {
    Socket socket;
    const auto invalid = socket.native_handle();
    CHECK_FALSE(socket.valid());
#if defined(_WIN32)
    CHECK(invalid == static_cast<Socket::native_handle_type>(INVALID_SOCKET));
#else
    CHECK(invalid == -1);
#endif
    socket.close();
    socket.close();
    CHECK_FALSE(socket.valid());
    CHECK(socket.native_handle() == invalid);
}

TEST_CASE("IPv4 UDP sockets have the requested type and configuration", "[socket]") {
    check_family_and_type(IpFamily::V4, SocketTransport::Udp);
}

TEST_CASE("IPv4 TCP sockets have the requested type and configuration", "[socket]") {
    check_family_and_type(IpFamily::V4, SocketTransport::Tcp);
}

TEST_CASE("IPv6 UDP sockets have the requested type and configuration", "[socket]") {
    check_family_and_type(IpFamily::V6, SocketTransport::Udp);
}

TEST_CASE("IPv6 TCP sockets have the requested type and configuration", "[socket]") {
    check_family_and_type(IpFamily::V6, SocketTransport::Tcp);
}

TEST_CASE("Closing a socket releases its handle and is idempotent", "[socket]") {
    auto runtime_guard = open_socket(IpFamily::V4, SocketTransport::Udp);
    auto socket = open_socket(IpFamily::V4, SocketTransport::Tcp);
    const auto handle = socket.native_handle();

    socket.close();
    check_closed_handle(handle);
    CHECK_FALSE(socket.valid());
    socket.close();
    CHECK_FALSE(socket.valid());
    CHECK(integer_option(runtime_guard.native_handle(), SO_TYPE) == SOCK_DGRAM);
}

TEST_CASE("Socket destruction releases its handle", "[socket]") {
    auto runtime_guard = open_socket(IpFamily::V4, SocketTransport::Udp);
    Socket::native_handle_type handle{};
    {
        auto socket = open_socket(IpFamily::V4, SocketTransport::Tcp);
        handle = socket.native_handle();
    }
    check_closed_handle(handle);
    CHECK(integer_option(runtime_guard.native_handle(), SO_TYPE) == SOCK_DGRAM);
}

TEST_CASE("Moving a socket transfers ownership through moved-from destruction", "[socket]") {
    Socket destination;
    Socket::native_handle_type handle{};
    {
        auto source = open_socket(IpFamily::V4, SocketTransport::Udp);
        handle = source.native_handle();
        Socket moved{std::move(source)};
        CHECK_FALSE(source.valid());
        CHECK(moved.native_handle() == handle);

        destination = std::move(moved);
        CHECK_FALSE(moved.valid());
    }
    REQUIRE(destination.valid());
    CHECK(destination.native_handle() == handle);
    CHECK(integer_option(destination.native_handle(), SO_TYPE) == SOCK_DGRAM);
}

TEST_CASE("Move assignment closes the old socket before taking the new one", "[socket]") {
    auto destination = open_socket(IpFamily::V4, SocketTransport::Udp);
    auto source = open_socket(IpFamily::V4, SocketTransport::Tcp);
    const auto old_handle = destination.native_handle();
    const auto transferred_handle = source.native_handle();
    REQUIRE(old_handle != transferred_handle);

    destination = std::move(source);
    check_closed_handle(old_handle);
    CHECK_FALSE(source.valid());
    CHECK(destination.native_handle() == transferred_handle);
    CHECK(integer_option(destination.native_handle(), SO_TYPE) == SOCK_STREAM);
}

TEST_CASE("Assigning an invalid socket releases the previous handle", "[socket]") {
    auto runtime_guard = open_socket(IpFamily::V4, SocketTransport::Udp);
    auto destination = open_socket(IpFamily::V4, SocketTransport::Tcp);
    const auto handle = destination.native_handle();
    Socket empty;

    destination = std::move(empty);
    check_closed_handle(handle);
    CHECK_FALSE(destination.valid());
    CHECK_FALSE(empty.valid());
    CHECK(integer_option(runtime_guard.native_handle(), SO_TYPE) == SOCK_DGRAM);
}

TEST_CASE("Self move assignment keeps a socket usable", "[socket]") {
    auto socket = open_socket(IpFamily::V4, SocketTransport::Udp);
    const auto handle = socket.native_handle();
    auto& same_socket = socket;

    socket = std::move(same_socket);
    REQUIRE(socket.valid());
    CHECK(socket.native_handle() == handle);
    CHECK(integer_option(socket.native_handle(), SO_TYPE) == SOCK_DGRAM);
}

TEST_CASE("A new UDP socket does not block while waiting for absent loopback data",
          "[socket][nonblocking]") {
    auto socket = open_socket(IpFamily::V4, SocketTransport::Udp);
    const auto handle = static_cast<NativeSocket>(socket.native_handle());
    sockaddr_in loopback{};
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    loopback.sin_port = 0;

    const int bound = ::bind(handle, reinterpret_cast<const sockaddr*>(&loopback),
                             static_cast<SocketLength>(sizeof(loopback)));
    const int bind_error = bound == 0 ? 0 : last_socket_error();
    CAPTURE(bind_error);
    REQUIRE(bound == 0);

    char byte{};
    const auto received = ::recv(handle, &byte, 1, 0);
    const int error = last_socket_error();
    CAPTURE(error);
    REQUIRE(received == -1);
#if defined(_WIN32)
    CHECK(error == WSAEWOULDBLOCK);
#else
    CHECK((error == EAGAIN || error == EWOULDBLOCK));
#endif
}

TEST_CASE("Invalid socket families return a deterministic creation error", "[socket][error]") {
    for (const int value : {-1, 2, 99}) {
        CAPTURE(value);
        const auto result = Socket::open(static_cast<IpFamily>(value), SocketTransport::Udp);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().operation == NetworkOperation::SocketCreate);
        CHECK(result.error().system_code == unsupported_family);
    }
}

TEST_CASE("Invalid socket transports return a deterministic creation error", "[socket][error]") {
    for (const int value : {-1, 2, 99}) {
        CAPTURE(value);
        const auto result = Socket::open(IpFamily::V4, static_cast<SocketTransport>(value));
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().operation == NetworkOperation::SocketCreate);
        CHECK(result.error().system_code == unsupported_transport);
    }
}

} // namespace
