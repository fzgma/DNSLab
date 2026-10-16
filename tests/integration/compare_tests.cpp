#include "app/compare.hpp"
#include "support/query_fixture.hpp"

#include <array>
#include <chrono>
#include <utility>
#include <variant>

namespace {

using namespace dnslab;
using namespace dnslab::test;
using namespace std::chrono_literals;

/// 断言预检期间没有向本地服务器发送查询。
void check_no_request(const UdpServer& server) {
    const auto request = net::receive_datagram(server.socket(), net::Deadline::after(30ms));
    REQUIRE_FALSE(request.has_value());
    CHECK(request.error().code == net::NetworkErrorCode::TimedOut);
}

/// 核对回退历史仍包含有效 UDP 截断响应及后续 TCP 尝试。
void check_fallback_history(const std::vector<app::QueryAttempt>& attempts) {
    REQUIRE(attempts.size() == 2);
    CHECK(attempts[0].transport == app::QueryTransport::Udp);
    REQUIRE(attempts[0].outcome.has_value());
    CHECK(attempts[0].outcome->header.truncated());
    CHECK(attempts[1].transport == app::QueryTransport::Tcp);
}

TEST_CASE("比较在全量预检失败时不向前面的有效端点发包", "[compare][validation][udp]") {
    UdpServer first;
    UdpServer second;
    auto invalid = second.endpoint();
    invalid.port = 0;
    const std::array bad_endpoints{first.endpoint(), invalid};
    const auto bad_endpoint = app::compare_servers(example_question(), bad_endpoints);
    REQUIRE_FALSE(bad_endpoint.has_value());
    CHECK(bad_endpoint.error().code == app::CompareErrorCode::InvalidEndpoint);
    CHECK(bad_endpoint.error().input_index == 1);
    check_no_request(first);

    const std::array duplicate_endpoints{first.endpoint(), second.endpoint(), first.endpoint()};
    const auto duplicate = app::compare_servers(example_question(), duplicate_endpoints);
    REQUIRE_FALSE(duplicate.has_value());
    CHECK(duplicate.error().code == app::CompareErrorCode::DuplicateEndpoint);
    CHECK(duplicate.error().input_index == 2);
    CHECK(duplicate.error().first_duplicate_index == 0);
    check_no_request(first);
    check_no_request(second);
}

TEST_CASE("比较在首台超时后继续且下一台拥有完整独立预算", "[compare][deadline][udp]") {
    UdpServer silent;
    UdpServer replying;
    WorkerState silent_state;
    WorkerState replying_state;
    /// 接收首台查询但保持端口开放且不应答，产生真实预算耗尽。
    auto silent_worker = start_worker(silent_state, [&](const net::Deadline& deadline, std::stop_token) {
        silent_state.request = silent.receive(deadline).bytes;
    });
    /// 第二台收到请求后再延迟应答，证明它没有继承第一台耗尽的预算。
    auto replying_worker = start_worker(replying_state,
        [&](const net::Deadline& deadline, std::stop_token stop) {
            const auto request = replying.receive(deadline);
            replying_state.request = request.bytes;
            if (!delay(stop, 150ms)) { return; }
            replying.send(request.sender, answer_response(request.bytes, AnswerKind::A), deadline);
        });
    const std::array servers{silent.endpoint(), replying.endpoint()};
    constexpr auto budget = 500ms;
    const auto result = app::compare_servers(example_question(), servers, app::TransportMode::Udp, budget);
    silent_worker.join();
    replying_worker.join();
    check_worker(silent_state);
    check_worker(replying_state);
    REQUIRE(result.has_value());
    CHECK(result->mode == app::TransportMode::Udp);
    CHECK(result->question.name.labels == example_question().name.labels);
    REQUIRE(result->entries.size() == 2);
    CHECK(result->entries[0].server == silent.endpoint());
    CHECK(result->entries[1].server == replying.endpoint());
    REQUIRE_FALSE(result->entries[0].outcome.has_value());
    const auto& failure = result->entries[0].outcome.error();
    CHECK(failure.code == app::QueryErrorCode::Timeout);
    CHECK(failure.elapsed >= budget);
    REQUIRE(failure.attempts.size() == 1);
    REQUIRE_FALSE(failure.attempts[0].outcome.has_value());
    REQUIRE(result->entries[1].outcome.has_value());
    const auto& success = *result->entries[1].outcome;
    check_answer(success, AnswerKind::A);
    CHECK(success.elapsed >= 150ms);
    CHECK(result->elapsed >= failure.elapsed + success.elapsed);
    CHECK(result->elapsed >= 650ms);
    CHECK_FALSE(app::compare_responses(result->entries[0], result->entries[1]).has_value());
}

TEST_CASE("比较按输入顺序查询并保留不同 DNS 响应码的成功结果", "[compare][order][udp]") {
    UdpServer first;
    UdpServer second;
    WorkerState state;
    dns::Packet second_request;
    /// 串行接收指定顺序的请求，用不同响应码标识结果归属。
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        const auto request = second.receive(deadline);
        state.request = request.bytes;
        second.send(request.sender, empty_response(request.bytes, 3), deadline);
        const auto next = first.receive(deadline);
        second_request = next.bytes;
        first.send(next.sender, empty_response(next.bytes, 2), deadline);
    });
    const std::array servers{second.endpoint(), first.endpoint()};
    const auto result = app::compare_servers(example_question(), servers, app::TransportMode::Udp, 1000ms);
    worker.join();
    check_worker(state);
    REQUIRE_FALSE(second_request.empty());
    REQUIRE(result.has_value());
    REQUIRE(result->entries.size() == 2);
    for (std::size_t index = 0; index < servers.size(); ++index) {
        CHECK(result->entries[index].server == servers[index]);
        REQUIRE(result->entries[index].outcome.has_value());
        CHECK(result->entries[index].outcome->server == servers[index]);
        REQUIRE(result->entries[index].outcome->attempts.size() == 1);
        CHECK(result->entries[index].outcome->attempts[0].outcome.has_value());
    }
    CHECK(result->entries[0].outcome->response.header.rcode() == 3);
    CHECK(result->entries[1].outcome->response.header.rcode() == 2);
    const auto differences = app::compare_responses(result->entries[0], result->entries[1]);
    REQUIRE(differences.has_value());
    CHECK(differences->rcode);
    CHECK_FALSE(differences->flags);
    CHECK_FALSE(differences->answers);
}

TEST_CASE("比较将显式 TCP 模式传递给每个目标", "[compare][tcp]") {
    TcpServer first;
    TcpServer second;
    WorkerState state;
    dns::Packet second_request;
    /// 两台均只提供 TCP 服务，逐台响应以验证模式没有退回默认 UDP。
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        auto first_stream = first.accept(deadline);
        state.request = first_stream.receive_frame(deadline);
        first_stream.send_frame(answer_response(state.request, AnswerKind::A), deadline);
        auto second_stream = second.accept(deadline);
        second_request = second_stream.receive_frame(deadline);
        second_stream.send_frame(answer_response(second_request, AnswerKind::A), deadline);
    });
    const std::array servers{first.endpoint(), second.endpoint()};
    const auto result = app::compare_servers(example_question(), servers, app::TransportMode::Tcp, 1000ms);
    worker.join();
    check_worker(state);
    REQUIRE_FALSE(second_request.empty());
    REQUIRE(result.has_value());
    CHECK(result->mode == app::TransportMode::Tcp);
    REQUIRE(result->entries.size() == 2);
    for (const auto& entry : result->entries) {
        REQUIRE(entry.outcome.has_value());
        CHECK(entry.outcome->transport == app::QueryTransport::Tcp);
        REQUIRE(entry.outcome->attempts.size() == 1);
        CHECK(entry.outcome->attempts.front().transport == app::QueryTransport::Tcp);
    }
    const auto differences = app::compare_responses(result->entries[0], result->entries[1]);
    REQUIRE(differences.has_value());
    CHECK_FALSE(differences->any());
}

TEST_CASE("比较在回退成功或失败时保留完整历史并继续下一台", "[compare][auto][tcp]") {
    for (const bool close_after_query : {false, true}) {
        CAPTURE(close_after_query);
        TcpServer tcp;
        UdpServer fallback{tcp.endpoint()};
        UdpServer next;
        WorkerState state;
        dns::Packet tcp_request;
        dns::Packet next_request;
        /// 先处理首台 UDP 与 TCP 回退，再返回第二台的普通 UDP 答案。
        auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
            const auto request = fallback.receive(deadline);
            state.request = request.bytes;
            fallback.send(request.sender, empty_response(request.bytes, 0, true), deadline);
            auto stream = tcp.accept(deadline);
            tcp_request = stream.receive_frame(deadline);
            if (close_after_query) {
                stream.shutdown_write();
            } else {
                stream.send_frame(answer_response(tcp_request, AnswerKind::A), deadline);
            }
            const auto following = next.receive(deadline);
            next_request = following.bytes;
            next.send(following.sender, answer_response(following.bytes, AnswerKind::A), deadline);
        });
        const std::array servers{fallback.endpoint(), next.endpoint()};
        const auto result = app::compare_servers(example_question(), servers, app::TransportMode::Auto, 1000ms);
        worker.join();
        check_worker(state);
        CHECK(tcp_request == state.request);
        REQUIRE_FALSE(next_request.empty());
        REQUIRE(result.has_value());
        REQUIRE(result->entries.size() == 2);
        const auto& first = result->entries[0].outcome;
        CHECK(first.has_value() == !close_after_query);
        if (close_after_query) {
            REQUIRE_FALSE(first.has_value());
            CHECK(first.error().code == app::QueryErrorCode::Network);
            check_fallback_history(first.error().attempts);
            CHECK_FALSE(first.error().attempts[1].outcome.has_value());
            REQUIRE(std::holds_alternative<net::NetworkError>(first.error().detail));
            CHECK(std::get<net::NetworkError>(first.error().detail).code ==
                  net::NetworkErrorCode::ConnectionClosed);
        } else {
            REQUIRE(first.has_value());
            check_fallback_history(first->attempts);
            REQUIRE(first->attempts[1].outcome.has_value());
            CHECK(first->transport == app::QueryTransport::Tcp);
        }
        REQUIRE(result->entries[1].outcome.has_value());
        CHECK(result->entries[1].outcome->transport == app::QueryTransport::Udp);
        REQUIRE(result->entries[1].outcome->attempts.size() == 1);
        check_answer(*result->entries[1].outcome, AnswerKind::A);
    }
}

} // 匿名命名空间
