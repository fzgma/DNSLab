#include "net/tcp.hpp"
#include "net/udp.hpp"
#include "support/tcp_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <string>
#include <thread>
#include <utility>

namespace {

using namespace dnslab::net;
using namespace std::chrono_literals;
using dnslab::test::TcpServer;
using dnslab::test::TcpStream;
using Packet = std::vector<std::byte>;

/// 生成长度可控且内容确定的字节序列用于检测传输缺失或改写。
Packet pattern(std::size_t size) {
    Packet result(size);
    for (std::size_t index = 0; index < size; ++index) {
        result[index] = static_cast<std::byte>((index * 37U) & 0xffU);
    }
    return result;
}

/// 在给定截止时间内连接本地测试服务器并返回客户端套接字。
Socket connect_to(const TcpServer& server, const Deadline& deadline) {
    auto socket = Socket::open(server.endpoint().family(), SocketTransport::Tcp);
    REQUIRE(socket.has_value());
    const auto connected = connect_socket(*socket, server.endpoint(), deadline);
    if (!connected) {
        CAPTURE(connected.error().system_code);
        REQUIRE(connected.has_value());
    }
    return std::move(*socket);
}

struct ConnectedPair {
    Socket client;
    TcpStream peer;
};

/// 建立一对相互连接的本地 TCP 流供收发边界测试使用。
ConnectedPair connected_pair() {
    TcpServer server;
    const auto deadline = Deadline::after(2s);
    auto client = connect_to(server, deadline);
    return {std::move(client), server.accept(deadline)};
}

/// 在主线程重新报告工作线程捕获的异常。
void check_worker(const std::exception_ptr& error) {
    if (error) {
        try {
            std::rethrow_exception(error);
        } catch (const std::exception& exception) {
            FAIL(exception.what());
        }
    }
}

/// 断言网络操作失败并保留预期错误类别、阶段及空系统码。
template <typename T>
void check_error(const std::expected<T, NetworkError>& result,
                 NetworkErrorCode code, NetworkOperation operation) {
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().operation == operation);
    CHECK(result.error().system_code == 0);
}

/// 设置原生套接字缓冲区大小以构造分段收发或背压条件。
void set_buffer(Socket::native_handle_type handle, int option, int size) {
#if defined(_WIN32)
    const auto result = ::setsockopt(static_cast<SOCKET>(handle), SOL_SOCKET, option,
                                     reinterpret_cast<const char*>(&size), sizeof(size));
#else
    const auto result = ::setsockopt(handle, SOL_SOCKET, option, &size, sizeof(size));
#endif
    REQUIRE(result == 0);
}

/// 验证指定地址族的 TCP 长度帧在双向传输中保留全部字节。
void check_roundtrip(IpFamily family) {
    TcpServer server{family};
    const auto deadline = Deadline::after(3s);
    auto client = connect_to(server, deadline);
    auto peer = server.accept(deadline);
    std::exception_ptr worker_error;
    std::vector<Packet> seen;
    /// 依次回显三种长度的消息，并记录收到的完整帧。
    std::jthread worker([&] {
        try {
            for (int iteration = 0; iteration < 3; ++iteration) {
                auto message = peer.receive_frame(deadline);
                seen.push_back(message);
                peer.send_frame(message, deadline);
            }
        } catch (...) {
            worker_error = std::current_exception();
        }
    });
    const std::array<std::size_t, 3> lengths{12, 257, 65535};
    for (const auto size : lengths) {
        const auto bytes = pattern(size);
        REQUIRE(send_tcp_message(client, bytes, deadline).has_value());
        const auto response = receive_tcp_message(client, deadline);
        REQUIRE(response.has_value());
        CHECK(*response == bytes);
    }
    worker.join();
    check_worker(worker_error);
    REQUIRE(seen.size() == lengths.size());
    for (std::size_t index = 0; index < lengths.size(); ++index) {
        CHECK(seen[index] == pattern(lengths[index]));
    }
}

TEST_CASE("IPv4 TCP 长度帧保留最小、最大和跨字节长度",
          "[tcp][ipv4][framing]") {
    check_roundtrip(IpFamily::V4);
}

TEST_CASE("IPv6 TCP 长度帧保留最小、最大和跨字节长度",
          "[tcp][ipv6][framing]") {
    check_roundtrip(IpFamily::V6);
}

TEST_CASE("TCP 接收分段前缀和正文且不消耗下一帧",
          "[tcp][framing][partial]") {
    auto pair = connected_pair();
    const auto deadline = Deadline::after(2s);
    const auto first = pattern(17);
    const auto second = pattern(12);
    std::exception_ptr worker_error;
    /// 分段发送两个连续帧以验证精确接收不会越过当前帧。
    std::jthread worker([&] {
        try {
            const std::array high{std::byte{0}};
            const std::array low{std::byte{17}};
            pair.peer.send_all(high, deadline);
            std::this_thread::sleep_for(20ms);
            pair.peer.send_all(low, deadline);
            pair.peer.send_all(std::span{first}.first(3), deadline);
            std::this_thread::sleep_for(20ms);
            Packet remaining(first.begin() + 3, first.end());
            remaining.push_back(std::byte{0});
            remaining.push_back(std::byte{12});
            remaining.insert(remaining.end(), second.begin(), second.end());
            pair.peer.send_all(remaining, deadline);
        } catch (...) {
            worker_error = std::current_exception();
        }
    });
    const auto received_first = receive_tcp_message(pair.client, deadline);
    const auto received_second = receive_tcp_message(pair.client, deadline);
    worker.join();
    check_worker(worker_error);
    REQUIRE(received_first.has_value());
    REQUIRE(received_second.has_value());
    CHECK(*received_first == first);
    CHECK(*received_second == second);
}

TEST_CASE("TCP 在小发送缓冲区下完成大数据流发送",
          "[tcp][partial][send]") {
    auto pair = connected_pair();
    set_buffer(pair.client.native_handle(), SO_SNDBUF, 4096);
    const auto bytes = pattern(1024 * 1024);
    const auto deadline = Deadline::after(3s);
    Packet received;
    std::exception_ptr worker_error;
    /// 读取全部大数据流并保留结果供发送完整性检查。
    std::jthread worker([&] {
        try {
            std::this_thread::sleep_for(30ms);
            received = pair.peer.receive_exact(bytes.size(), deadline);
        } catch (...) {
            worker_error = std::current_exception();
        }
    });
    const auto sent = send_all(pair.client, bytes, deadline);
    worker.join();
    check_worker(worker_error);
    REQUIRE(sent.has_value());
    CHECK(received == bytes);
}

TEST_CASE("TCP 发送缓冲区满后仍遵守截止时间",
          "[tcp][deadline][send]") {
    auto pair = connected_pair();
    set_buffer(pair.client.native_handle(), SO_SNDBUF, 4096);
    set_buffer(pair.peer.native_handle(), SO_RCVBUF, 4096);
    const std::array<std::byte, 4096> bytes{};
    const auto preparation = Deadline::after(2s);
    std::size_t queued = 0;
    bool blocked = false;
    // Winsock 可能接受超出 SO_SNDBUF 的一次大写入，因此先用小块原生写入填满缓冲区，
    // 确认暂时不可写后再验证生产代码的等待行为。
    while (!preparation.expired() && queued < 1024 * 1024) {
#if defined(_WIN32)
        const auto count = ::send(static_cast<SOCKET>(pair.client.native_handle()),
            reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
        const int error = count < 0 ? ::WSAGetLastError() : 0;
        const bool interrupted = error == WSAEINTR;
        const bool would_block = error == WSAEWOULDBLOCK;
#else
        const auto count = ::send(pair.client.native_handle(), bytes.data(),
                                   bytes.size(), MSG_NOSIGNAL);
        const int error = count < 0 ? errno : 0;
        const bool interrupted = error == EINTR;
        const bool would_block = error == EAGAIN || error == EWOULDBLOCK;
#endif
        if (count > 0) {
            queued += static_cast<std::size_t>(count);
        } else if (count < 0 && interrupted) {
            continue;
        } else if (count < 0 && would_block) {
            // 第一次暂时不可写可能在已排队字节获得确认后解除，
            // 因此继续填充，直到背压保持稳定。
            const Deadline settle{std::min(preparation.expires_at(),
                Deadline::Clock::now() + 250ms)};
            const auto writable = wait_socket(pair.client, WaitInterest::Write, settle);
            if (writable) {
                continue;
            }
            REQUIRE(writable.error().code == NetworkErrorCode::TimedOut);
            blocked = true;
            break;
        } else {
            CAPTURE(count, error);
            FAIL("原生数据流在形成背压前准备失败");
        }
    }
    REQUIRE(queued > 0);
    REQUIRE(blocked);
    REQUIRE_FALSE(preparation.expired());
    const auto started_at = Deadline::Clock::now();
    const auto deadline = Deadline::after(80ms, started_at);
    const auto sent = send_all(pair.client, bytes, deadline);
    const auto elapsed = Deadline::Clock::now() - started_at;
    REQUIRE_FALSE(sent.has_value());
    CHECK(sent.error().code == NetworkErrorCode::TimedOut);
    CHECK(sent.error().system_code == 0);
    CHECK(elapsed >= 80ms);
    CHECK(elapsed < 1s);
    CHECK(deadline.expires_at() == started_at + 80ms);
}

TEST_CASE("TCP 部分接收后连接关闭明确报告操作未完成",
          "[tcp][eof][partial]") {
    auto pair = connected_pair();
    const auto deadline = Deadline::after(2s);
    const auto sent = pattern(5);
    pair.peer.send_all(sent, deadline);
    pair.peer.shutdown_write();
    std::array<std::byte, 8> buffer{};
    check_error(receive_exact(pair.client, buffer, deadline),
                 NetworkErrorCode::ConnectionClosed, NetworkOperation::Receive);
    CHECK(Packet(buffer.begin(), buffer.begin() + 5) == sent);
}

TEST_CASE("TCP 长度帧拒绝前缀或正文中的提前关闭",
          "[tcp][framing][eof]") {
    const std::array<Packet, 4> prefixes{
        Packet{}, Packet{std::byte{0}}, Packet{std::byte{0}, std::byte{12}},
        Packet{std::byte{0}, std::byte{12}, std::byte{1}, std::byte{2}},
    };
    for (const auto& bytes : prefixes) {
        CAPTURE(bytes.size());
        auto pair = connected_pair();
        const auto deadline = Deadline::after(2s);
        pair.peer.send_all(bytes, deadline);
        pair.peer.shutdown_write();
        check_error(receive_tcp_message(pair.client, deadline),
                     NetworkErrorCode::ConnectionClosed, NetworkOperation::Receive);
    }
}

TEST_CASE("TCP 长度帧拒绝所有小于 DNS 首部的声明长度",
          "[tcp][framing][invalid]") {
    for (unsigned length = 0; length < 12; ++length) {
        CAPTURE(length);
        auto pair = connected_pair();
        const auto deadline = Deadline::after(2s);
        const std::array prefix{std::byte{0}, static_cast<std::byte>(length)};
        pair.peer.send_all(prefix, deadline);
        check_error(receive_tcp_message(pair.client, deadline),
                     NetworkErrorCode::InvalidMessageLength, NetworkOperation::Receive);
    }
}

TEST_CASE("TCP 在发送前缀前拒绝无效的待发送帧长度",
          "[tcp][framing][invalid]") {
    auto pair = connected_pair();
    const auto deadline = Deadline::after(2s);
    for (const std::size_t length : {0U, 1U, 11U, 65536U}) {
        CAPTURE(length);
        check_error(send_tcp_message(pair.client, Packet(length), deadline),
                     NetworkErrorCode::InvalidMessageLength, NetworkOperation::Send);
    }
    bool timed_out = false;
    try {
        (void)pair.peer.receive_exact(1, Deadline::after(30ms));
    } catch (const dnslab::test::FixtureError& error) {
        timed_out = error.timed_out;
    }
    CHECK(timed_out);
}

TEST_CASE("TCP 连接被拒绝时保留原生连接错误",
          "[tcp][connect][error]") {
    auto reserved = Socket::open(IpFamily::V4, SocketTransport::Tcp);
    REQUIRE(reserved.has_value());
    const auto loopback = parse_endpoint("127.0.0.1");
    REQUIRE(loopback.has_value());
    auto requested = *loopback;
    requested.port = 0;
    REQUIRE(bind_socket(*reserved, requested).has_value());
    const auto bound = local_endpoint(*reserved);
    REQUIRE(bound.has_value());
    auto client = Socket::open(IpFamily::V4, SocketTransport::Tcp);
    REQUIRE(client.has_value());
    // 整个尝试期间保留端口但不监听，避免关闭再绑定产生端口复用竞态。
    // Windows 可能重试回环 SYN 约两秒后才报告拒绝连接。
    // 本用例检查原生拒绝错误，与短预算用例分开验证。
    const auto result = connect_socket(*client, *bound, Deadline::after(5s));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().operation == NetworkOperation::Connect);
    CHECK(result.error().code == NetworkErrorCode::System);
#if defined(_WIN32)
    CHECK(result.error().system_code == WSAECONNREFUSED);
#else
    CHECK(result.error().system_code == ECONNREFUSED);
#endif
}

TEST_CASE("TCP 连接重置保留系统错误且后续写入不触发 SIGPIPE",
          "[tcp][reset][send]") {
    auto pair = connected_pair();
    const auto deadline = Deadline::after(2s);
    pair.peer.reset();
    std::array<std::byte, 1> byte{};
    const auto received = receive_exact(pair.client, byte, deadline);
    REQUIRE_FALSE(received.has_value());
    CHECK(received.error().code == NetworkErrorCode::System);
    CHECK(received.error().operation == NetworkOperation::Receive);
    CHECK(received.error().system_code != 0);
    const auto sent = send_all(pair.client, byte, deadline);
    REQUIRE_FALSE(sent.has_value());
    CHECK(sent.error().code == NetworkErrorCode::System);
    CHECK(sent.error().operation == NetworkOperation::Send);
    CHECK(sent.error().system_code != 0);
}

TEST_CASE("TCP 前缀和逐字节正文共用一次接收截止时间",
          "[tcp][framing][deadline]") {
    auto pair = connected_pair();
    const auto producer_deadline = Deadline::after(2s);
    const auto started_at = Deadline::Clock::now();
    const auto deadline = Deadline::after(90ms, started_at);
    std::exception_ptr worker_error;
    std::size_t sent_count = 0;
    /// 缓慢发送前缀及正文以验证部分接收不会重置预算。
    std::jthread worker([&](std::stop_token stop) {
        try {
            const std::array prefix{std::byte{0}, std::byte{12}};
            const std::array byte{std::byte{0x42}};
            pair.peer.send_all(prefix, producer_deadline);
            while (!stop.stop_requested() && sent_count < 12) {
                pair.peer.send_all(byte, producer_deadline);
                ++sent_count;
                std::this_thread::sleep_for(20ms);
            }
        } catch (...) {
            worker_error = std::current_exception();
        }
    });
    const auto received = receive_tcp_message(pair.client, deadline);
    const auto elapsed = Deadline::Clock::now() - started_at;
    worker.request_stop();
    worker.join();
    check_worker(worker_error);
    REQUIRE_FALSE(received.has_value());
    CHECK(received.error().code == NetworkErrorCode::TimedOut);
    CHECK(received.error().system_code == 0);
    CHECK(sent_count > 0);
    CHECK(sent_count < 12);
    CHECK(elapsed >= 90ms);
    CHECK(elapsed < 1s);
    CHECK(deadline.expires_at() == started_at + 90ms);
}

TEST_CASE("TCP 拒绝无效参数和已过期预算且不建立连接",
          "[tcp][invalid][deadline]") {
    TcpServer server;
    const auto deadline = Deadline::after(2s);
    Socket invalid;
    std::array<std::byte, 12> bytes{};
    check_error(connect_socket(invalid, server.endpoint(), deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::Connect);
    check_error(send_all(invalid, bytes, deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::Send);
    check_error(receive_exact(invalid, bytes, deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::Receive);
    check_error(send_tcp_message(invalid, bytes, deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::Send);
    check_error(receive_tcp_message(invalid, deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::Receive);

    auto client = Socket::open(IpFamily::V4, SocketTransport::Tcp);
    REQUIRE(client.has_value());
    auto zero_port = server.endpoint();
    zero_port.port = 0;
    check_error(connect_socket(*client, zero_port, deadline),
                 NetworkErrorCode::InvalidArgument, NetworkOperation::Connect);
    const Deadline expired{Deadline::Clock::now()};
    check_error(connect_socket(*client, server.endpoint(), expired),
                 NetworkErrorCode::TimedOut, NetworkOperation::Connect);
    CHECK_FALSE(server.pending(Deadline::after(30ms)));
    check_error(send_all(*client, {}, expired),
                 NetworkErrorCode::TimedOut, NetworkOperation::Send);
    check_error(receive_exact(*client, {}, expired),
                 NetworkErrorCode::TimedOut, NetworkOperation::Receive);
    check_error(send_tcp_message(*client, bytes, expired),
                 NetworkErrorCode::TimedOut, NetworkOperation::Send);
    check_error(receive_tcp_message(*client, expired),
                 NetworkErrorCode::TimedOut, NetworkOperation::Receive);

    auto pair = connected_pair();
    REQUIRE(send_all(pair.client, {}, deadline).has_value());
    REQUIRE(receive_exact(pair.client, {}, deadline).has_value());
}

} // 匿名命名空间
