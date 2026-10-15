#pragma once

#include "app/query.hpp"
#include "dns/wire_codec.hpp"
#include "support/tcp_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <stop_token>
#include <thread>
#include <utility>

namespace dnslab::test {

using namespace std::chrono_literals;
inline constexpr std::uint16_t query_id = 0x1234;

/// 构造固定域名和指定类型的查询，供集成用例复用。
inline dns::DnsQuestion example_question(std::uint16_t type = 1) {
    return {dns::DnsName{{"example", "com"}}, type, 1};
}

/// 复用查询问题并设置指定响应码及截断标志，生成空回答响应。
inline dns::Packet empty_response(const dns::Packet& query,
                                  unsigned int rcode = 0, bool truncated = false) {
    auto response = query;
    response.at(2) = truncated ? std::byte{0x83} : std::byte{0x81};
    response.at(3) = static_cast<std::byte>(0x80U | rcode);
    return response;
}

enum class AnswerKind { A, Aaaa, Cname };

/// 用固定字节生成 A、AAAA 或压缩 CNAME 回答。
inline dns::Packet answer_response(const dns::Packet& query, AnswerKind kind) {
    auto response = empty_response(query);
    response.at(7) = std::byte{1};
    response.insert(response.end(), {std::byte{0xc0}, std::byte{0x0c}});
    if (kind == AnswerKind::A) {
        response.insert(response.end(), {
            std::byte{0}, std::byte{1}, std::byte{0}, std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{60},
            std::byte{0}, std::byte{4},
            std::byte{192}, std::byte{0}, std::byte{2}, std::byte{10}});
    } else if (kind == AnswerKind::Aaaa) {
        response.insert(response.end(), {
            std::byte{0}, std::byte{28}, std::byte{0}, std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{60},
            std::byte{0}, std::byte{16},
            std::byte{0x20}, std::byte{0x01}, std::byte{0x0d}, std::byte{0xb8},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}});
    } else {
        response.insert(response.end(), {
            std::byte{0}, std::byte{5}, std::byte{0}, std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{60},
            std::byte{0}, std::byte{8},
            std::byte{5}, std::byte{0x61}, std::byte{0x6c}, std::byte{0x69},
            std::byte{0x61}, std::byte{0x73}, std::byte{0xc0}, std::byte{0x0c}});
    }
    return response;
}

/// 核对查询结果中的名称、类型、类别、TTL 和回答值。
inline void check_answer(const app::QueryResult& result, AnswerKind kind) {
    REQUIRE(result.response.answers.size() == 1);
    const auto& answer = result.response.answers.front();
    CHECK(answer.owner.labels == std::vector<std::string>{"example", "com"});
    CHECK(answer.rr_class == 1);
    CHECK(answer.ttl == 60);
    if (kind == AnswerKind::A) {
        REQUIRE(std::holds_alternative<dns::AData>(answer.rdata));
        CHECK(std::get<dns::AData>(answer.rdata).address ==
              std::array<std::byte, 4>{std::byte{192}, std::byte{0},
                                       std::byte{2}, std::byte{10}});
    } else if (kind == AnswerKind::Aaaa) {
        REQUIRE(std::holds_alternative<dns::AaaaData>(answer.rdata));
        const std::array<std::byte, 16> address{
            std::byte{0x20}, std::byte{0x01}, std::byte{0x0d}, std::byte{0xb8},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
        CHECK(std::get<dns::AaaaData>(answer.rdata).address == address);
    } else {
        REQUIRE(std::holds_alternative<dns::NameData>(answer.rdata));
        CHECK(std::get<dns::NameData>(answer.rdata).name.labels ==
              std::vector<std::string>{"alias", "example", "com"});
    }
}

struct WorkerState {
    dns::Packet request;
    std::exception_ptr exception;
};

/// 启动带固定截止时间的服务器线程并把异常保存给主线程。
template <typename Function>
std::jthread start_worker(WorkerState& state, Function function) {
    /// 运行测试服务器处理器并捕获异常，避免异常逃出线程入口。
    return std::jthread{[&state, function = std::move(function)](std::stop_token stop) {
        try {
            function(net::Deadline::after(3000ms), stop);
        } catch (...) {
            state.exception = std::current_exception();
        }
    }};
}

/// 在主线程检查服务器异常并确认其确实收到查询请求。
inline void check_worker(const WorkerState& state) {
    if (state.exception) {
        try {
            std::rethrow_exception(state.exception);
        } catch (const std::exception& error) {
            FAIL("本地服务器失败: " << error.what());
        }
    }
    REQUIRE_FALSE(state.request.empty());
}

// 模拟可取消的网络延迟，使测试退出时可通过停止请求及时结束等待。
/// 模拟可由停止令牌提前结束的网络延迟。
inline bool delay(std::stop_token stop, std::chrono::milliseconds duration) {
    std::mutex mutex;
    std::unique_lock lock{mutex};
    std::condition_variable_any condition;
    /// 保持等待条件为假，仅由超时或停止请求结束模拟延迟。
    condition.wait_for(lock, stop, duration, [] { return false; });
    return !stop.stop_requested();
}

class UdpServer {
public:
    /// 在指定回环端点绑定 UDP 测试服务器并保存实际端口。
    explicit UdpServer(net::Endpoint endpoint =
                          tcp_fixture_detail::loopback(net::IpFamily::V4, 0)) {
        auto opened = net::Socket::open(endpoint.family(), net::SocketTransport::Udp);
        if (!opened) {
            throw FixtureError("UDP 服务器套接字创建失败", opened.error().system_code);
        }
        socket_ = std::move(*opened);
        const auto bound = net::bind_socket(socket_, endpoint);
        if (!bound) {
            throw FixtureError("UDP 服务器地址绑定失败", bound.error().system_code);
        }
        const auto local = net::local_endpoint(socket_);
        if (!local) {
            throw FixtureError("UDP 服务器端点读取失败", local.error().system_code);
        }
        endpoint_ = *local;
    }

    /// 返回 UDP 服务器实际绑定的地址和端口。
    [[nodiscard]] const net::Endpoint& endpoint() const noexcept { return endpoint_; }
    /// 借用 UDP 服务器套接字进行额外的被动收包检查。
    [[nodiscard]] const net::Socket& socket() const noexcept { return socket_; }

    /// 接收一份完整 UDP 数据报并保留来源或原生失败详情。
    [[nodiscard]] net::Datagram receive(const net::Deadline& deadline) const {
        auto received = net::receive_datagram(socket_, deadline);
        if (!received) {
            throw FixtureError("UDP 服务器接收失败", received.error().system_code,
                received.error().code == net::NetworkErrorCode::TimedOut);
        }
        return std::move(*received);
    }

    /// 在指定截止时间内向目标端点发送一份 UDP 响应。
    void send(const net::Endpoint& destination, const dns::Packet& packet,
              const net::Deadline& deadline) const {
        const auto sent = net::send_datagram(socket_, destination, packet, deadline);
        if (!sent) {
            throw FixtureError("UDP 服务器发送失败", sent.error().system_code,
                sent.error().code == net::NetworkErrorCode::TimedOut);
        }
    }

private:
    net::Socket socket_;
    net::Endpoint endpoint_{};
};

/// 使用独立固定字节核对客户端发出的 DNS 查询。
inline void check_request(const dns::Packet& request, std::uint16_t type = 1) {
    // 使用固定报文字节独立验证发往服务器的请求，避免重复依赖生产编码器。
    dns::Packet expected{
        std::byte{0x12}, std::byte{0x34}, std::byte{1}, std::byte{0},
        std::byte{0}, std::byte{1}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{7}, std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
        std::byte{'m'}, std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
        std::byte{3}, std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
        std::byte{0}, std::byte{0}, static_cast<std::byte>(type),
        std::byte{0}, std::byte{1}};
    CHECK(request == expected);
}

} // 命名空间 dnslab::test
