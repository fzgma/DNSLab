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

/// 立即读取当前平台最近一次套接字操作的错误码。
int last_socket_error() noexcept {
#if defined(_WIN32)
    return ::WSAGetLastError();
#else
    return errno;
#endif
}

/// 创建指定类型的测试套接字并在失败时记录原始错误。
Socket open_socket(IpFamily family, SocketTransport transport) {
    auto result = Socket::open(family, transport);
    if (!result) {
        CAPTURE(static_cast<int>(family), static_cast<int>(transport),
                static_cast<int>(result.error().operation), result.error().system_code);
        REQUIRE(result.has_value());
    }
    return std::move(*result);
}

/// 读取并校验原生套接字整数选项。
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

// 调用本辅助函数时，关闭操作前已打开的守护套接字仍然存活。
// 关闭句柄与验证失效之间不创建新套接字，避免句柄复用造成误判。
/// 通过原生选项查询确认关闭后的句柄确实失效。
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

/// 检查套接字地址族、传输类型、非阻塞及平台句柄配置。
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

TEST_CASE("默认套接字无效且可重复关闭", "[socket]") {
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

TEST_CASE("IPv4 UDP 套接字具有请求的类型与配置", "[socket]") {
    check_family_and_type(IpFamily::V4, SocketTransport::Udp);
}

TEST_CASE("IPv4 TCP 套接字具有请求的类型与配置", "[socket]") {
    check_family_and_type(IpFamily::V4, SocketTransport::Tcp);
}

TEST_CASE("IPv6 UDP 套接字具有请求的类型与配置", "[socket]") {
    check_family_and_type(IpFamily::V6, SocketTransport::Udp);
}

TEST_CASE("IPv6 TCP 套接字具有请求的类型与配置", "[socket]") {
    check_family_and_type(IpFamily::V6, SocketTransport::Tcp);
}

TEST_CASE("关闭套接字释放句柄且重复关闭无副作用", "[socket]") {
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

TEST_CASE("套接字析构释放句柄", "[socket]") {
    auto runtime_guard = open_socket(IpFamily::V4, SocketTransport::Udp);
    Socket::native_handle_type handle{};
    {
        auto socket = open_socket(IpFamily::V4, SocketTransport::Tcp);
        handle = socket.native_handle();
    }
    check_closed_handle(handle);
    CHECK(integer_option(runtime_guard.native_handle(), SO_TYPE) == SOCK_DGRAM);
}

TEST_CASE("套接字移动转移所有权且源对象析构不影响目标", "[socket]") {
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

TEST_CASE("移动赋值先关闭旧套接字再接管新套接字", "[socket]") {
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

TEST_CASE("赋入无效套接字释放原有句柄", "[socket]") {
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

TEST_CASE("套接字自移动赋值后仍可使用", "[socket]") {
    auto socket = open_socket(IpFamily::V4, SocketTransport::Udp);
    const auto handle = socket.native_handle();
    auto& same_socket = socket;

    socket = std::move(same_socket);
    REQUIRE(socket.valid());
    CHECK(socket.native_handle() == handle);
    CHECK(integer_option(socket.native_handle(), SO_TYPE) == SOCK_DGRAM);
}

TEST_CASE("新 UDP 套接字等待不存在的回环数据时不阻塞",
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

TEST_CASE("无效地址族返回确定的套接字创建错误", "[socket][error]") {
    for (const int value : {-1, 2, 99}) {
        CAPTURE(value);
        const auto result = Socket::open(static_cast<IpFamily>(value), SocketTransport::Udp);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().operation == NetworkOperation::SocketCreate);
        CHECK(result.error().system_code == unsupported_family);
    }
}

TEST_CASE("无效传输类型返回确定的套接字创建错误", "[socket][error]") {
    for (const int value : {-1, 2, 99}) {
        CAPTURE(value);
        const auto result = Socket::open(IpFamily::V4, static_cast<SocketTransport>(value));
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().operation == NetworkOperation::SocketCreate);
        CHECK(result.error().system_code == unsupported_transport);
    }
}

} // 匿名命名空间
