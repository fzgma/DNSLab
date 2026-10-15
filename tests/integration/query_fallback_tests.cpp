#include "support/query_fixture.hpp"

#include <array>
#include <optional>
#include <variant>

namespace {

using namespace dnslab;
using namespace dnslab::test;
using namespace std::chrono_literals;

/// 断言尝试记录恰为一次成功的 UDP 截断响应和后续 TCP 查询。
void check_two_attempts(const std::vector<app::QueryAttempt>& attempts) {
    REQUIRE(attempts.size() == 2);
    CHECK(attempts[0].transport == app::QueryTransport::Udp);
    REQUIRE(attempts[0].outcome.has_value());
    CHECK(attempts[0].outcome->header.truncated());
    CHECK(attempts[1].transport == app::QueryTransport::Tcp);
}

/// 验证自动回退共用同一端点、问题、事务 ID 和原始查询报文。
void check_fallback_success(net::IpFamily family, bool generated_id = false,
                            bool final_truncated = false) {
    TcpServer tcp{family};
    UdpServer udp{tcp.endpoint()};
    REQUIRE(udp.endpoint() == tcp.endpoint());
    const auto kind = family == net::IpFamily::V6 ? AnswerKind::Aaaa : AnswerKind::A;
    const auto type = static_cast<std::uint16_t>(kind == AnswerKind::Aaaa ? 28 : 1);
    const auto question = example_question(type);
    WorkerState state;
    dns::Packet tcp_request;
    /// 先返回 UDP 截断响应，再接收同一查询并发送 TCP 回答。
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        const auto request = udp.receive(deadline);
        state.request = request.bytes;
        udp.send(request.sender, empty_response(state.request, 0, true), deadline);
        auto stream = tcp.accept(deadline);
        tcp_request = stream.receive_frame(deadline);
        auto response = answer_response(tcp_request, kind);
        if (final_truncated) {
            response[2] |= std::byte{0x02};
        }
        stream.send_frame(response, deadline);
    });
    const auto id = generated_id ? std::nullopt : std::optional{query_id};
    const auto result = app::query_server(question, tcp.endpoint(),
                                         app::TransportMode::Auto, 1500ms, id);
    worker.join();
    check_worker(state);
    CHECK(tcp_request == state.request);
    REQUIRE(result.has_value());
    CHECK(result->server == tcp.endpoint());
    CHECK(result->question.name.labels == question.name.labels);
    CHECK(result->question.type == question.type);
    CHECK(result->question.qclass == question.qclass);
    CHECK(result->transport == app::QueryTransport::Tcp);
    CHECK(result->response.header.id == result->transaction_id);
    CHECK(result->response.header.truncated() == final_truncated);
    if (generated_id) {
        REQUIRE(state.request.size() >= 2);
        const auto sent_id = (std::to_integer<unsigned int>(state.request[0]) << 8U) |
                             std::to_integer<unsigned int>(state.request[1]);
        CHECK(result->transaction_id == sent_id);
        auto normalized_request = state.request;
        normalized_request[0] = std::byte{0x12};
        normalized_request[1] = std::byte{0x34};
        check_request(normalized_request, type);
    } else {
        CHECK(result->transaction_id == query_id);
        check_request(state.request, type);
    }
    check_answer(*result, kind);
    check_two_attempts(result->attempts);
    REQUIRE(result->attempts[1].outcome.has_value());
    CHECK(result->attempts[0].outcome->header.id == result->transaction_id);
    CHECK(result->attempts[0].outcome->answers.empty());
    CHECK(result->attempts[1].outcome->header.id == result->transaction_id);
    CHECK(result->attempts[1].outcome->header.truncated() == final_truncated);
    CHECK(result->ignored_messages == 0);
    CHECK(result->attempts[0].ignored_messages == 0);
    CHECK(result->attempts[1].ignored_messages == 0);
    CHECK(result->attempts[0].elapsed + result->attempts[1].elapsed <= result->elapsed);
    CHECK_FALSE(tcp.pending(net::Deadline::after(30ms)));
    const auto extra = net::receive_datagram(udp.socket(), net::Deadline::after(30ms));
    REQUIRE_FALSE(extra.has_value());
    CHECK(extra.error().code == net::NetworkErrorCode::TimedOut);
}

enum class BadTc { Id, Qr, Opcode, Count, Name, Type, Class, Malformed };

/// 构造带 TC 但不能通过解析或事务匹配的响应。
dns::Packet bad_tc_response(const dns::Packet& query, BadTc rejection) {
    auto response = empty_response(query, 0, true);
    switch (rejection) {
    case BadTc::Id:
        response[1] ^= std::byte{1};
        break;
    case BadTc::Qr:
        response[2] &= std::byte{0x7f};
        break;
    case BadTc::Opcode:
        response[2] |= std::byte{0x08};
        break;
    case BadTc::Count:
        response[5] = std::byte{0};
        response.resize(12);
        break;
    case BadTc::Name:
        response[13] = std::byte{'x'};
        break;
    case BadTc::Type:
        response[response.size() - 3] = std::byte{28};
        break;
    case BadTc::Class:
        response.back() = std::byte{3};
        break;
    case BadTc::Malformed:
        response.resize(12); // 保留的 QDCOUNT 仍声明存在已被截去的问题。
        break;
    }
    return response;
}

} // 匿名命名空间

TEST_CASE("自动模式在匹配的 IPv4 UDP 截断响应后使用同一查询回退", "[query][auto]") {
    check_fallback_success(net::IpFamily::V4);
}

TEST_CASE("自动模式在匹配的 IPv6 UDP 截断响应后使用同一查询回退", "[query][auto][ipv6]") {
    check_fallback_success(net::IpFamily::V6);
}

TEST_CASE("自动模式只生成一个供 UDP 和 TCP 共用的事务 ID", "[query][auto]") {
    check_fallback_success(net::IpFamily::V4, true);
}

TEST_CASE("自动模式保留 TCP 截断响应且不启动第三次尝试", "[query][auto]") {
    check_fallback_success(net::IpFamily::V4, false, true);
}

TEST_CASE("自动模式在 TCP 关闭或帧错误时保留 UDP 截断响应", "[query][auto]") {
    for (const bool invalid_length : {false, true}) {
        CAPTURE(invalid_length);
        TcpServer tcp;
        UdpServer udp{tcp.endpoint()};
        WorkerState state;
        dns::Packet tcp_request;
        /// 先返回 UDP 截断响应，再构造 TCP 关闭或帧错误。
        auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
            const auto request = udp.receive(deadline);
            state.request = request.bytes;
            udp.send(request.sender, empty_response(state.request, 0, true), deadline);
            auto stream = tcp.accept(deadline);
            tcp_request = stream.receive_frame(deadline);
            if (invalid_length) {
                const std::array prefix{std::byte{0}, std::byte{11}};
                stream.send_all(prefix, deadline);
            }
            stream.shutdown_write();
        });
        const auto result = app::query_server(example_question(), tcp.endpoint(),
                                             app::TransportMode::Auto, 1500ms, query_id);
        worker.join();
        check_worker(state);
        CHECK(tcp_request == state.request);
        REQUIRE_FALSE(result.has_value());
        const auto& error = result.error();
        CHECK(error.code == (invalid_length ? app::QueryErrorCode::InvalidResponse
                                            : app::QueryErrorCode::Network));
        REQUIRE(std::holds_alternative<net::NetworkError>(error.detail));
        const auto& network_error = std::get<net::NetworkError>(error.detail);
        CHECK(network_error.operation == net::NetworkOperation::Receive);
        CHECK(network_error.code == (invalid_length ? net::NetworkErrorCode::InvalidMessageLength
                                                    : net::NetworkErrorCode::ConnectionClosed));
        check_two_attempts(error.attempts);
        REQUIRE_FALSE(error.attempts[1].outcome.has_value());
        CHECK(error.attempts[1].outcome.error().code == error.code);
        REQUIRE(std::holds_alternative<net::NetworkError>(error.attempts[1].outcome.error().detail));
        CHECK(std::get<net::NetworkError>(error.attempts[1].outcome.error().detail).code ==
              network_error.code);
        CHECK(error.attempts[0].elapsed + error.attempts[1].elapsed <= error.elapsed);
        CHECK(error.ignored_messages == 0);
    }
}

TEST_CASE("自动模式在 TCP 连接被拒绝时保留 UDP 截断响应", "[query][auto]") {
    auto reserved = net::Socket::open(net::IpFamily::V4, net::SocketTransport::Tcp);
    REQUIRE(reserved.has_value());
    const auto bound = net::bind_socket(*reserved,
        tcp_fixture_detail::loopback(net::IpFamily::V4, 0));
    REQUIRE(bound.has_value());
    const auto local = net::local_endpoint(*reserved);
    REQUIRE(local.has_value());
    const auto endpoint = *local;
    // 保留端口但不监听，避免拒绝连接测试与端口复用发生竞态。
    UdpServer udp{endpoint};
    WorkerState state;
    /// 发送 UDP 截断响应，让客户端尝试连接未监听的 TCP 端口。
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        const auto request = udp.receive(deadline);
        state.request = request.bytes;
        udp.send(request.sender, empty_response(state.request, 0, true), deadline);
    });
    // Windows 可能重试本地连接超过两秒后才
    // 报告拒绝；本用例检查该错误，短超时另有用例覆盖。
    const auto result = app::query_server(example_question(), endpoint,
                                         app::TransportMode::Auto, 5000ms, query_id);
    worker.join();
    check_worker(state);
    REQUIRE_FALSE(result.has_value());
    const auto& error = result.error();
    CHECK(error.code == app::QueryErrorCode::Network);
    REQUIRE(std::holds_alternative<net::NetworkError>(error.detail));
    CHECK(std::get<net::NetworkError>(error.detail).operation == net::NetworkOperation::Connect);
    CHECK(std::get<net::NetworkError>(error.detail).system_code != 0);
    check_two_attempts(error.attempts);
    REQUIRE_FALSE(error.attempts[1].outcome.has_value());
    CHECK(error.attempts[1].outcome.error().code == app::QueryErrorCode::Network);
}

TEST_CASE("显式 UDP 保留截断响应且不打开 TCP 连接", "[query][auto]") {
    TcpServer tcp;
    UdpServer udp{tcp.endpoint()};
    WorkerState state;
    /// 返回 UDP 截断响应以验证显式 UDP 模式不会回退。
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        const auto request = udp.receive(deadline);
        state.request = request.bytes;
        udp.send(request.sender, empty_response(state.request, 0, true), deadline);
    });
    const auto result = app::query_server(example_question(), tcp.endpoint(),
                                         app::TransportMode::Udp, 1500ms, query_id);
    worker.join();
    check_worker(state);
    REQUIRE(result.has_value());
    CHECK(result->transport == app::QueryTransport::Udp);
    CHECK(result->response.header.truncated());
    REQUIRE(result->attempts.size() == 1);
    REQUIRE(result->attempts[0].outcome.has_value());
    CHECK(result->attempts[0].outcome->header.truncated());
    CHECK_FALSE(tcp.pending(net::Deadline::after(30ms)));
}

TEST_CASE("自动模式接受非截断 UDP 响应及 DNS 错误码且不连接 TCP", "[query][auto]") {
    for (const auto rcode : {0U, 2U, 3U}) {
        CAPTURE(rcode);
        TcpServer tcp;
        UdpServer udp{tcp.endpoint()};
        WorkerState state;
        /// 返回非截断 UDP 响应以验证自动模式直接结束。
        auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
            const auto request = udp.receive(deadline);
            state.request = request.bytes;
            udp.send(request.sender, empty_response(state.request, rcode), deadline);
        });
        const auto result = app::query_server(example_question(), tcp.endpoint(),
                                             app::TransportMode::Auto, 1500ms, query_id);
        worker.join();
        check_worker(state);
        REQUIRE(result.has_value());
        CHECK(result->transport == app::QueryTransport::Udp);
        CHECK(result->response.header.rcode() == rcode);
        REQUIRE(result->attempts.size() == 1);
        CHECK_FALSE(tcp.pending(net::Deadline::after(30ms)));
    }
}

TEST_CASE("自动模式 UDP 超时不连接 TCP 也不重传", "[query][auto]") {
    TcpServer tcp;
    UdpServer udp{tcp.endpoint()};
    const auto result = app::query_server(example_question(), tcp.endpoint(),
                                         app::TransportMode::Auto, 150ms, query_id);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == app::QueryErrorCode::Timeout);
    CHECK(result.error().ignored_messages == 0);
    REQUIRE(result.error().attempts.size() == 1);
    CHECK(result.error().attempts[0].transport == app::QueryTransport::Udp);
    REQUIRE_FALSE(result.error().attempts[0].outcome.has_value());
    CHECK(result.error().attempts[0].outcome.error().code == app::QueryErrorCode::Timeout);
    CHECK_FALSE(tcp.pending(net::Deadline::after(30ms)));
    check_request(udp.receive(net::Deadline::after(100ms)).bytes);
    const auto duplicate = net::receive_datagram(udp.socket(), net::Deadline::after(30ms));
    REQUIRE_FALSE(duplicate.has_value());
    CHECK(duplicate.error().code == net::NetworkErrorCode::TimedOut);
}

TEST_CASE("自动模式忽略其他 UDP 来源的截断响应且不连接 TCP", "[query][auto]") {
    TcpServer tcp;
    UdpServer udp{tcp.endpoint()};
    UdpServer stranger;
    REQUIRE(stranger.endpoint() != udp.endpoint());
    WorkerState state;
    /// 从不同 UDP 来源发送截断响应以验证来源校验。
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        const auto request = udp.receive(deadline);
        state.request = request.bytes;
        stranger.send(request.sender, empty_response(state.request, 0, true), deadline);
    });
    const auto result = app::query_server(example_question(), tcp.endpoint(),
                                         app::TransportMode::Auto, 150ms, query_id);
    worker.join();
    check_worker(state);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == app::QueryErrorCode::Timeout);
    CHECK(std::holds_alternative<std::monostate>(result.error().detail));
    CHECK(result.error().ignored_messages == 1);
    REQUIRE(result.error().attempts.size() == 1);
    CHECK_FALSE(tcp.pending(net::Deadline::after(30ms)));
}

TEST_CASE("自动模式在考虑回退前拒绝畸形和不匹配的 UDP 截断响应", "[query][auto]") {
    for (const auto rejection : {BadTc::Id, BadTc::Qr, BadTc::Opcode, BadTc::Count,
                                 BadTc::Name, BadTc::Type, BadTc::Class, BadTc::Malformed}) {
        CAPTURE(static_cast<int>(rejection));
        TcpServer tcp;
        UdpServer udp{tcp.endpoint()};
        WorkerState state;
        /// 返回无法通过校验的截断响应以验证不触发回退。
        auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
            const auto request = udp.receive(deadline);
            state.request = request.bytes;
            udp.send(request.sender, bad_tc_response(state.request, rejection), deadline);
        });
        const auto result = app::query_server(example_question(), tcp.endpoint(),
                                             app::TransportMode::Auto, 150ms, query_id);
        worker.join();
        check_worker(state);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == app::QueryErrorCode::InvalidResponse);
        CHECK(result.error().ignored_messages == 1);
        REQUIRE(result.error().attempts.size() == 1);
        CHECK(result.error().attempts[0].transport == app::QueryTransport::Udp);
        if (rejection == BadTc::Malformed) {
            REQUIRE(std::holds_alternative<dns::DnsParseError>(result.error().detail));
            CHECK(std::get<dns::DnsParseError>(result.error().detail).code ==
                  dns::DnsParseErrorCode::SectionCountMismatch);
        } else {
            CHECK(std::holds_alternative<app::ResponseMismatch>(result.error().detail));
        }
        CHECK_FALSE(tcp.pending(net::Deadline::after(30ms)));
    }
}

TEST_CASE("自动模式拒绝截断响应后仍可接受后续非截断 UDP 响应", "[query][auto]") {
    for (const auto rejection : {BadTc::Id, BadTc::Malformed}) {
        CAPTURE(static_cast<int>(rejection));
        TcpServer tcp;
        UdpServer udp{tcp.endpoint()};
        WorkerState state;
        /// 先发送无效截断响应，再发送有效非截断响应。
        auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
            const auto request = udp.receive(deadline);
            state.request = request.bytes;
            udp.send(request.sender, bad_tc_response(state.request, rejection), deadline);
            udp.send(request.sender, answer_response(state.request, AnswerKind::A), deadline);
        });
        const auto result = app::query_server(example_question(), tcp.endpoint(),
                                             app::TransportMode::Auto, 1500ms, query_id);
        worker.join();
        check_worker(state);
        REQUIRE(result.has_value());
        CHECK(result->transport == app::QueryTransport::Udp);
        CHECK_FALSE(result->response.header.truncated());
        CHECK(result->ignored_messages == 1);
        REQUIRE(result->attempts.size() == 1);
        CHECK(result->attempts[0].ignored_messages == 1);
        check_answer(*result, AnswerKind::A);
        CHECK_FALSE(tcp.pending(net::Deadline::after(30ms)));
    }
}

TEST_CASE("自动模式分别记录 UDP 和 TCP 忽略的消息", "[query][auto]") {
    TcpServer tcp;
    UdpServer udp{tcp.endpoint()};
    WorkerState state;
    dns::Packet tcp_request;
    /// 分别向 UDP 与 TCP 发送无效消息和有效响应以验证独立计数。
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        const auto request = udp.receive(deadline);
        state.request = request.bytes;
        udp.send(request.sender, bad_tc_response(state.request, BadTc::Id), deadline);
        udp.send(request.sender, empty_response(state.request, 0, true), deadline);
        auto stream = tcp.accept(deadline);
        tcp_request = stream.receive_frame(deadline);
        stream.send_frame(bad_tc_response(tcp_request, BadTc::Name), deadline);
        stream.send_frame(answer_response(tcp_request, AnswerKind::A), deadline);
    });
    const auto result = app::query_server(example_question(), tcp.endpoint(),
                                         app::TransportMode::Auto, 1500ms, query_id);
    worker.join();
    check_worker(state);
    CHECK(tcp_request == state.request);
    REQUIRE(result.has_value());
    CHECK(result->ignored_messages == 2);
    check_two_attempts(result->attempts);
    REQUIRE(result->attempts[1].outcome.has_value());
    CHECK(result->attempts[0].ignored_messages == 1);
    CHECK(result->attempts[1].ignored_messages == 1);
    check_answer(*result, AnswerKind::A);
}

TEST_CASE("自动模式的 UDP 延迟与 TCP 延迟消耗同一总预算", "[query][auto]") {
    TcpServer tcp;
    UdpServer udp{tcp.endpoint()};
    WorkerState state;
    dns::Packet tcp_request;
    /// 在 UDP 和 TCP 两阶段分别引入延迟，检验共享总预算。
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token stop) {
        const auto request = udp.receive(deadline);
        state.request = request.bytes;
        if (!delay(stop, 400ms)) { return; }
        udp.send(request.sender, empty_response(state.request, 0, true), deadline);
        auto stream = tcp.accept(deadline);
        tcp_request = stream.receive_frame(deadline);
        // 此响应可落在重新分配的 TCP 预算内，但已超过原查询总预算。
        if (!delay(stop, 500ms)) { return; }
        stream.send_frame(answer_response(tcp_request, AnswerKind::A), deadline);
    });
    const auto result = app::query_server(example_question(), tcp.endpoint(),
                                         app::TransportMode::Auto, 800ms, query_id);
    worker.request_stop();
    worker.join();
    check_worker(state);
    REQUIRE_FALSE(tcp_request.empty());
    CHECK(tcp_request == state.request);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == app::QueryErrorCode::Timeout);
    CHECK(result.error().elapsed >= 800ms);
    check_two_attempts(result.error().attempts);
    REQUIRE_FALSE(result.error().attempts[1].outcome.has_value());
    CHECK(result.error().attempts[1].outcome.error().code == app::QueryErrorCode::Timeout);
    CHECK(result.error().attempts[0].elapsed >= 400ms);
    CHECK(result.error().attempts[0].elapsed + result.error().attempts[1].elapsed <=
          result.error().elapsed);
}

TEST_CASE("无效自动查询输入既不发送 UDP 也不连接 TCP", "[query][auto]") {
    TcpServer tcp;
    UdpServer udp{tcp.endpoint()};
    /// 核对无效输入的错误类别且确认没有任何传输尝试。
    const auto check_error = [](const auto& result, app::QueryErrorCode code) {
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == code);
        CHECK(result.error().attempts.empty());
        CHECK(result.error().ignored_messages == 0);
    };
    check_error(app::query_server(example_question(), tcp.endpoint(),
                                  static_cast<app::TransportMode>(99), 1500ms, query_id),
                app::QueryErrorCode::InvalidMode);
    for (const auto budget : {99ms, 30001ms}) {
        check_error(app::query_server(example_question(), tcp.endpoint(),
                                      app::TransportMode::Auto, budget, query_id),
                    app::QueryErrorCode::InvalidTimeout);
    }
    auto endpoint = tcp.endpoint();
    endpoint.port = 0;
    check_error(app::query_server(example_question(), endpoint,
                                  app::TransportMode::Auto, 1500ms, query_id),
                app::QueryErrorCode::InvalidEndpoint);
    auto invalid_name = example_question();
    invalid_name.name.labels.push_back("");
    auto invalid_class = example_question();
    invalid_class.qclass = 3;
    for (const auto& question : {invalid_name, example_question(5), invalid_class}) {
        check_error(app::query_server(question, tcp.endpoint(),
                                      app::TransportMode::Auto, 1500ms, query_id),
                    app::QueryErrorCode::Encode);
    }
    CHECK_FALSE(tcp.pending(net::Deadline::after(30ms)));
    const auto unexpected = net::receive_datagram(udp.socket(), net::Deadline::after(30ms));
    REQUIRE_FALSE(unexpected.has_value());
    CHECK(unexpected.error().code == net::NetworkErrorCode::TimedOut);
}
