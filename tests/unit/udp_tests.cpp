#include "net/udp.hpp"

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
#include <sys/socket.h>
#endif

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <optional>
#include <thread>
#include <utility>

namespace {

using namespace dnslab::net;
using namespace std::chrono_literals;

struct BoundSocket {
    Socket socket;
    Endpoint endpoint;
};

/// 绑定指定地址族的 UDP 回环临时端口并返回实际端点。
BoundSocket bind_loopback(IpFamily family) {
    auto socket = Socket::open(family, SocketTransport::Udp);
    if (!socket) {
        CAPTURE(socket.error().system_code);
        REQUIRE(socket.has_value());
    }
    Endpoint requested{Ipv4Address{std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1}}, 0};
    if (family == IpFamily::V6) {
        Ipv6Address address{};
        address.back() = std::byte{1};
        requested.address = address;
    }
    const auto bound = bind_socket(*socket, requested);
    if (!bound) {
        CAPTURE(bound.error().system_code);
        REQUIRE(bound.has_value());
    }
    const auto endpoint = local_endpoint(*socket);
    REQUIRE(endpoint.has_value());
    CHECK(endpoint->family() == family);
    CHECK(endpoint->address == requested.address);
    REQUIRE(endpoint->port != 0);
    return {std::move(*socket), *endpoint};
}

/// 断言 UDP 操作返回指定错误类别、操作阶段和空系统码。
template <typename T>
void check_error(const std::expected<T, NetworkError>& result,
                 NetworkErrorCode code, NetworkOperation operation) {
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().operation == operation);
    CHECK(result.error().system_code == 0);
}

/// 通过原生接口验证 UDP 套接字未被隐式连接到单一对端。
void check_unconnected(const Socket& socket) {
    sockaddr_storage peer{};
#if defined(_WIN32)
    auto length = static_cast<int>(sizeof(peer));
    const int result = ::getpeername(static_cast<SOCKET>(socket.native_handle()),
                                     reinterpret_cast<sockaddr*>(&peer), &length);
    const int error = ::WSAGetLastError();
    constexpr int not_connected = WSAENOTCONN;
#else
    auto length = static_cast<socklen_t>(sizeof(peer));
    const int result = ::getpeername(socket.native_handle(),
                                     reinterpret_cast<sockaddr*>(&peer), &length);
    const int error = errno;
    constexpr int not_connected = ENOTCONN;
#endif
    REQUIRE(result == -1);
    CHECK(error == not_connected);
}

/// 验证指定地址族的 UDP 往返保留来源、普通负载和空数据报。
void check_roundtrip(IpFamily family) {
    auto server = bind_loopback(family);
    auto client = bind_loopback(family);
    const auto deadline = Deadline::after(2s);
    const std::array<std::vector<std::byte>, 2> payloads{
        std::vector{std::byte{0}, std::byte{0xff}, std::byte{0x80}, std::byte{1}},
        std::vector<std::byte>{},
    };
    for (const auto& payload : payloads) {
        CAPTURE(payload.size());
        REQUIRE(send_datagram(client.socket, server.endpoint, payload, deadline).has_value());
        REQUIRE(wait_socket(server.socket, WaitInterest::Read, deadline).has_value());
        const auto request = receive_datagram(server.socket, deadline);
        REQUIRE(request.has_value());
        CHECK(request->bytes == payload);
        CHECK(request->sender == client.endpoint);

        REQUIRE(send_datagram(server.socket, request->sender, request->bytes, deadline).has_value());
        const auto response = receive_datagram(client.socket, deadline);
        REQUIRE(response.has_value());
        CHECK(response->bytes == payload);
        CHECK(response->sender == server.endpoint);
    }
    check_unconnected(server.socket);
    check_unconnected(client.socket);
}

TEST_CASE("IPv4 UDP 使用回环临时端点并保留空数据报",
          "[udp][ipv4]") {
    check_roundtrip(IpFamily::V4);
}

TEST_CASE("IPv6 UDP 使用回环临时端点并保留空数据报",
          "[udp][ipv6]") {
    check_roundtrip(IpFamily::V6);
}

TEST_CASE("UDP 接收报告每个实际来源且不自行过滤",
          "[udp][source]") {
    auto server = bind_loopback(IpFamily::V4);
    auto first = bind_loopback(IpFamily::V4);
    auto second = bind_loopback(IpFamily::V4);
    const auto deadline = Deadline::after(2s);
    const std::array payload{std::byte{42}};
    for (auto* sender : {&first, &second}) {
        REQUIRE(send_datagram(sender->socket, server.endpoint, payload, deadline).has_value());
        const auto received = receive_datagram(server.socket, deadline);
        REQUIRE(received.has_value());
        CHECK(received->sender == sender->endpoint);
        CHECK(received->bytes == std::vector<std::byte>(payload.begin(), payload.end()));
    }
}

TEST_CASE("UDP 完整接收大数据报而不返回截断前缀",
          "[udp][size]") {
    auto server = bind_loopback(IpFamily::V4);
    auto client = bind_loopback(IpFamily::V4);
    std::vector<std::byte> bytes(60000);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(index & 0xffU);
    }
    const auto deadline = Deadline::after(2s);
    REQUIRE(send_datagram(client.socket, server.endpoint, bytes, deadline).has_value());
    const auto received = receive_datagram(server.socket, deadline);
    REQUIRE(received.has_value());
    CHECK(received->bytes == bytes);
    CHECK(received->sender == client.endpoint);
}

TEST_CASE("UDP 等待后到的本地数据时沿用原截止时间",
          "[udp][wait]") {
    auto server = bind_loopback(IpFamily::V4);
    auto client = bind_loopback(IpFamily::V4);
    const auto deadline = Deadline::after(2s);
    std::optional<NetworkError> worker_error;
    const std::array payload{std::byte{0xab}, std::byte{0xcd}};
    /// 延迟发送本地数据，以验证接收端等待后到数据。
    std::jthread sender([&] {
        std::this_thread::sleep_for(20ms);
        const auto result = send_datagram(client.socket, server.endpoint, payload, deadline);
        if (!result) {
            worker_error = result.error();
        }
    });
    const auto received = receive_datagram(server.socket, deadline);
    sender.join();
    CHECK_FALSE(worker_error.has_value());
    REQUIRE(received.has_value());
    CHECK(received->bytes == std::vector<std::byte>(payload.begin(), payload.end()));
    CHECK(received->sender == client.endpoint);
}

TEST_CASE("UDP 就绪等待遵守有限和已过期的截止时间",
          "[udp][deadline]") {
    auto server = bind_loopback(IpFamily::V4);
    const auto deadline = Deadline::after(35ms);
    check_error(wait_socket(server.socket, WaitInterest::Read, deadline),
                 NetworkErrorCode::TimedOut, NetworkOperation::WaitRead);
    CHECK(deadline.expired());
    check_error(wait_socket(server.socket, WaitInterest::Write, deadline),
                 NetworkErrorCode::TimedOut, NetworkOperation::WaitWrite);
    check_error(receive_datagram(server.socket, deadline),
                 NetworkErrorCode::TimedOut, NetworkOperation::Receive);

    // 转换原生超时值前先限制上界；可写状态应立即返回。
    REQUIRE(wait_socket(server.socket, WaitInterest::Write,
                         Deadline{Deadline::TimePoint::max()}).has_value());
}

TEST_CASE("UDP 发送预算已过期时不发送数据报",
          "[udp][deadline]") {
    auto server = bind_loopback(IpFamily::V4);
    auto client = bind_loopback(IpFamily::V4);
    const Deadline expired{Deadline::Clock::now()};
    const std::array payload{std::byte{7}};
    check_error(send_datagram(client.socket, server.endpoint, payload, expired),
                 NetworkErrorCode::TimedOut, NetworkOperation::Send);
    const auto received = receive_datagram(server.socket, Deadline::after(35ms));
    REQUIRE_FALSE(received.has_value());
    CHECK(received.error().code == NetworkErrorCode::TimedOut);
    CHECK(received.error().system_code == 0);
}

TEST_CASE("连续 UDP 数据到达不会延长接收预算",
          "[udp][deadline]") {
    auto server = bind_loopback(IpFamily::V4);
    auto client = bind_loopback(IpFamily::V4);
    const std::array payload{std::byte{1}};
    const auto started_at = Deadline::Clock::now();
    const auto deadline = Deadline::after(60ms, started_at);
    const auto producer_deadline = Deadline::after(1s, started_at);
    REQUIRE(send_datagram(client.socket, server.endpoint, payload, producer_deadline).has_value());
    std::optional<NetworkError> worker_error;
    /// 持续发送 UDP 数据，以验证接收截止时间不会重置。
    std::jthread sender([&](std::stop_token stop) {
        while (!stop.stop_requested() && !producer_deadline.expired()) {
            const auto result = send_datagram(client.socket, server.endpoint, payload,
                                               producer_deadline);
            if (!result) {
                worker_error = result.error();
                break;
            }
            std::this_thread::sleep_for(5ms);
        }
    });
    std::size_t received_count = 0;
    std::optional<NetworkError> receive_error;
    for (;;) {
        const auto result = receive_datagram(server.socket, deadline);
        if (!result) {
            receive_error = result.error();
            break;
        }
        ++received_count;
    }
    const auto elapsed = Deadline::Clock::now() - started_at;
    sender.request_stop();
    sender.join();
    CHECK_FALSE(worker_error.has_value());
    REQUIRE(receive_error.has_value());
    CHECK(receive_error->code == NetworkErrorCode::TimedOut);
    CHECK(received_count > 0);
    CHECK(elapsed >= 60ms);
    CHECK(elapsed < 500ms);
    CHECK(deadline.expires_at() == started_at + 60ms);
}

TEST_CASE("UDP 操作拒绝无效套接字、等待方向、端口和负载长度",
          "[udp][invalid]") {
    Socket invalid;
    auto server = bind_loopback(IpFamily::V4);
    const auto deadline = Deadline::after(2s);
    check_error(bind_socket(invalid, server.endpoint), NetworkErrorCode::InvalidArgument,
                 NetworkOperation::Bind);
    check_error(local_endpoint(invalid), NetworkErrorCode::InvalidArgument,
                 NetworkOperation::LocalEndpoint);
    check_error(wait_socket(invalid, WaitInterest::Read, deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::WaitRead);
    check_error(wait_socket(server.socket, static_cast<WaitInterest>(99), deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::WaitRead);
    check_error(send_datagram(invalid, server.endpoint, {}, deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::Send);
    check_error(receive_datagram(invalid, deadline), NetworkErrorCode::InvalidArgument,
                 NetworkOperation::Receive);
    auto zero_port = server.endpoint;
    zero_port.port = 0;
    check_error(send_datagram(server.socket, zero_port, {}, deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::Send);
    const std::vector<std::byte> oversized(65536);
    check_error(send_datagram(server.socket, server.endpoint, oversized, deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::Send);
}

TEST_CASE("UDP 绑定失败保留原生错误及操作阶段",
          "[udp][error]") {
    auto server = bind_loopback(IpFamily::V4);
    const auto result = bind_socket(server.socket, server.endpoint);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == NetworkErrorCode::System);
    CHECK(result.error().operation == NetworkOperation::Bind);
    CHECK(result.error().system_code != 0);

    server.socket.close();
    check_error(local_endpoint(server.socket), NetworkErrorCode::InvalidArgument,
                 NetworkOperation::LocalEndpoint);
}

} // 匿名命名空间
