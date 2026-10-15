#include "support/query_fixture.hpp"

#include <array>
#include <span>
#include <variant>

namespace {

using namespace dnslab;
using namespace dnslab::test;
using namespace std::chrono_literals;

void check_tcp_answer(net::IpFamily family, AnswerKind kind) {
    TcpServer server{family};
    WorkerState state;
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        auto stream = server.accept(deadline);
        state.request = stream.receive_frame(deadline);
        stream.send_frame(answer_response(state.request, kind), deadline);
    });
    const auto type = static_cast<std::uint16_t>(kind == AnswerKind::Aaaa ? 28 : 1);
    const auto result = app::query_server(example_question(type), server.endpoint(),
                                         app::TransportMode::Tcp, 1500ms, query_id);
    worker.join();
    check_worker(state);
    check_request(state.request, type);
    REQUIRE(result.has_value());
    CHECK(result->server == server.endpoint());
    CHECK(result->transaction_id == query_id);
    CHECK(result->transport == app::QueryTransport::Tcp);
    CHECK(result->response.header.id == query_id);
    CHECK(result->response.header.rcode() == 0);
    CHECK(result->ignored_messages == 0);
    REQUIRE(result->attempts.size() == 1);
    CHECK(result->attempts[0].transport == app::QueryTransport::Tcp);
    REQUIRE(result->attempts[0].outcome.has_value());
    CHECK(result->attempts[0].elapsed <= result->elapsed);
    check_answer(*result, kind);
}

void append_frame(dns::Packet& destination, const dns::Packet& packet) {
    destination.push_back(static_cast<std::byte>(packet.size() >> 8));
    destination.push_back(static_cast<std::byte>(packet.size() & 0xffU));
    destination.insert(destination.end(), packet.begin(), packet.end());
}

} // namespace

TEST_CASE("Local IPv4 TCP queries preserve A AAAA and CNAME answers", "[query][tcp]") {
    for (const auto kind : {AnswerKind::A, AnswerKind::Aaaa, AnswerKind::Cname}) {
        CAPTURE(static_cast<int>(kind));
        check_tcp_answer(net::IpFamily::V4, kind);
    }
}

TEST_CASE("Local IPv6 TCP queries preserve A AAAA and CNAME answers", "[query][tcp][ipv6]") {
    for (const auto kind : {AnswerKind::A, AnswerKind::Aaaa, AnswerKind::Cname}) {
        CAPTURE(static_cast<int>(kind));
        check_tcp_answer(net::IpFamily::V6, kind);
    }
}

TEST_CASE("TCP queries retain empty answers and DNS error rcodes", "[query][tcp]") {
    for (const auto rcode : {0U, 2U, 3U}) {
        CAPTURE(rcode);
        TcpServer server;
        WorkerState state;
        auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
            auto stream = server.accept(deadline);
            state.request = stream.receive_frame(deadline);
            stream.send_frame(empty_response(state.request, rcode), deadline);
        });
        const auto result = app::query_server(example_question(), server.endpoint(),
                                             app::TransportMode::Tcp, 1500ms, query_id);
        worker.join();
        check_worker(state);
        REQUIRE(result.has_value());
        CHECK(result->response.header.rcode() == rcode);
        CHECK(result->response.answers.empty());
        REQUIRE(result->attempts.size() == 1);
        REQUIRE(result->attempts[0].outcome.has_value());
        CHECK(result->attempts[0].outcome->header.rcode() == rcode);
    }
}

TEST_CASE("TCP query assembles fragmented prefix and response body", "[query][tcp]") {
    TcpServer server;
    WorkerState state;
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token stop) {
        auto stream = server.accept(deadline);
        state.request = stream.receive_frame(deadline);
        const auto response = answer_response(state.request, AnswerKind::A);
        const std::byte high[]{std::byte{0}};
        const std::byte low[]{static_cast<std::byte>(response.size())};
        stream.send_all(high, deadline);
        if (!delay(stop, 15ms)) { return; }
        stream.send_all(low, deadline);
        stream.send_all(std::span{response}.first(7), deadline);
        if (!delay(stop, 15ms)) { return; }
        stream.send_all(std::span{response}.subspan(7, 9), deadline);
        stream.send_all(std::span{response}.subspan(16), deadline);
    });
    const auto result = app::query_server(example_question(), server.endpoint(),
                                         app::TransportMode::Tcp, 1500ms, query_id);
    worker.join();
    check_worker(state);
    REQUIRE(result.has_value());
    check_answer(*result, AnswerKind::A);
    CHECK(result->ignored_messages == 0);
}

TEST_CASE("TCP query skips malformed and mismatched frames before a valid frame", "[query][tcp]") {
    TcpServer server;
    WorkerState state;
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        auto stream = server.accept(deadline);
        state.request = stream.receive_frame(deadline);
        auto malformed = empty_response(state.request);
        malformed.resize(12); // QDCOUNT still requires an absent question.
        auto mismatch = empty_response(state.request);
        mismatch[1] ^= std::byte{1};
        dns::Packet frames;
        append_frame(frames, malformed);
        append_frame(frames, mismatch);
        append_frame(frames, answer_response(state.request, AnswerKind::Cname));
        stream.send_all(frames, deadline);
    });
    const auto result = app::query_server(example_question(), server.endpoint(),
                                         app::TransportMode::Tcp, 1500ms, query_id);
    worker.join();
    check_worker(state);
    REQUIRE(result.has_value());
    check_answer(*result, AnswerKind::Cname);
    CHECK(result->ignored_messages == 2);
    REQUIRE(result->attempts.size() == 1);
    CHECK(result->attempts[0].ignored_messages == 2);
}

TEST_CASE("TCP query accepts a complete 65535 byte DNS message", "[query][tcp]") {
    TcpServer server;
    WorkerState state;
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        auto stream = server.accept(deadline);
        state.request = stream.receive_frame(deadline);
        auto response = empty_response(state.request);
        response.at(7) = std::byte{1};
        response.insert(response.end(), {
            std::byte{0xc0}, std::byte{0x0c}, std::byte{0xfd}, std::byte{0xe8},
            std::byte{0}, std::byte{1}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{60}, std::byte{0xff}, std::byte{0xd6}});
        response.resize(65535, std::byte{0xa5});
        stream.send_frame(response, deadline);
    });
    const auto result = app::query_server(example_question(), server.endpoint(),
                                         app::TransportMode::Tcp, 1500ms, query_id);
    worker.join();
    check_worker(state);
    REQUIRE(result.has_value());
    REQUIRE(result->response.answers.size() == 1);
    CHECK(result->response.answers[0].type == 65000);
    const auto& rdata = result->response.answers[0].rdata;
    REQUIRE(std::holds_alternative<dns::OpaqueData>(rdata));
    CHECK(std::get<dns::OpaqueData>(rdata).bytes == dns::Packet(65494, std::byte{0xa5}));
}

TEST_CASE("TCP query rejects zero and undersized frame lengths", "[query][tcp]") {
    for (const auto length : {0U, 1U, 11U}) {
        CAPTURE(length);
        TcpServer server;
        WorkerState state;
        auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
            auto stream = server.accept(deadline);
            state.request = stream.receive_frame(deadline);
            const std::byte prefix[]{std::byte{0}, static_cast<std::byte>(length)};
            stream.send_all(prefix, deadline);
        });
        const auto result = app::query_server(example_question(), server.endpoint(),
                                             app::TransportMode::Tcp, 1500ms, query_id);
        worker.join();
        check_worker(state);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == app::QueryErrorCode::InvalidResponse);
        REQUIRE(std::holds_alternative<net::NetworkError>(result.error().detail));
        CHECK(std::get<net::NetworkError>(result.error().detail).code ==
              net::NetworkErrorCode::InvalidMessageLength);
        REQUIRE(result.error().attempts.size() == 1);
        CHECK_FALSE(result.error().attempts[0].outcome.has_value());
    }
}

TEST_CASE("TCP EOF before a response or within a frame remains a network error", "[query][tcp]") {
    const std::array<dns::Packet, 3> partial_frames{
        dns::Packet{}, dns::Packet{std::byte{0}},
        dns::Packet{std::byte{0}, std::byte{12}, std::byte{0x12}, std::byte{0x34}}};
    for (const auto& partial : partial_frames) {
        CAPTURE(partial.size());
        TcpServer server;
        WorkerState state;
        auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
            auto stream = server.accept(deadline);
            state.request = stream.receive_frame(deadline);
            stream.send_all(partial, deadline);
            stream.shutdown_write();
        });
        const auto result = app::query_server(example_question(), server.endpoint(),
                                             app::TransportMode::Tcp, 1500ms, query_id);
        worker.join();
        check_worker(state);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == app::QueryErrorCode::Network);
        REQUIRE(std::holds_alternative<net::NetworkError>(result.error().detail));
        CHECK(std::get<net::NetworkError>(result.error().detail).code ==
              net::NetworkErrorCode::ConnectionClosed);
    }
}

TEST_CASE("TCP EOF after an invalid DNS frame retains the transport failure", "[query][tcp]") {
    TcpServer server;
    WorkerState state;
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        auto stream = server.accept(deadline);
        state.request = stream.receive_frame(deadline);
        auto response = empty_response(state.request);
        response.resize(12);
        stream.send_frame(response, deadline);
        stream.shutdown_write();
    });
    const auto result = app::query_server(example_question(), server.endpoint(),
                                         app::TransportMode::Tcp, 1500ms, query_id);
    worker.join();
    check_worker(state);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == app::QueryErrorCode::Network);
    CHECK(result.error().ignored_messages == 1);
    REQUIRE(std::holds_alternative<net::NetworkError>(result.error().detail));
    CHECK(std::get<net::NetworkError>(result.error().detail).code ==
          net::NetworkErrorCode::ConnectionClosed);
}

TEST_CASE("TCP connection refusal is a network error with one attempt", "[query][tcp]") {
    auto reserved = net::Socket::open(net::IpFamily::V4, net::SocketTransport::Tcp);
    REQUIRE(reserved.has_value());
    const auto loopback = tcp_fixture_detail::loopback(net::IpFamily::V4, 0);
    REQUIRE(net::bind_socket(*reserved, loopback).has_value());
    const auto endpoint = net::local_endpoint(*reserved);
    REQUIRE(endpoint.has_value());
    // Hold the port without listening throughout the connection attempt. Allow
    // Windows localhost refusal retries to finish; deadline tests use shorter budgets.
    const auto result = app::query_server(example_question(), *endpoint,
                                         app::TransportMode::Tcp, 5000ms, query_id);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == app::QueryErrorCode::Network);
    REQUIRE(std::holds_alternative<net::NetworkError>(result.error().detail));
    CHECK(std::get<net::NetworkError>(result.error().detail).operation ==
          net::NetworkOperation::Connect);
    CHECK(std::get<net::NetworkError>(result.error().detail).code ==
          net::NetworkErrorCode::System);
    CHECK(std::get<net::NetworkError>(result.error().detail).system_code != 0);
    REQUIRE(result.error().attempts.size() == 1);
    CHECK(result.error().attempts[0].transport == app::QueryTransport::Tcp);
}

TEST_CASE("TCP timeout distinguishes no response from rejected responses", "[query][tcp]") {
    for (const bool send_invalid : {false, true}) {
        CAPTURE(send_invalid);
        TcpServer server;
        WorkerState state;
        auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token stop) {
            auto stream = server.accept(deadline);
            state.request = stream.receive_frame(deadline);
            if (send_invalid) {
                auto response = empty_response(state.request);
                response[1] ^= std::byte{1};
                stream.send_frame(response, deadline);
            }
            delay(stop, 2000ms);
        });
        const auto result = app::query_server(example_question(), server.endpoint(),
                                             app::TransportMode::Tcp, 150ms, query_id);
        worker.request_stop();
        worker.join();
        check_worker(state);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == (send_invalid ? app::QueryErrorCode::InvalidResponse
                                                  : app::QueryErrorCode::Timeout));
        CHECK(result.error().ignored_messages == (send_invalid ? 1U : 0U));
        if (send_invalid) {
            REQUIRE(std::holds_alternative<app::ResponseMismatch>(result.error().detail));
            CHECK(std::get<app::ResponseMismatch>(result.error().detail) ==
                  app::ResponseMismatch::TransactionId);
        }
    }
}

TEST_CASE("TCP truncation is returned without another query attempt", "[query][tcp]") {
    TcpServer server;
    UdpServer udp{server.endpoint()};
    WorkerState state;
    auto worker = start_worker(state, [&](const net::Deadline& deadline, std::stop_token) {
        auto stream = server.accept(deadline);
        state.request = stream.receive_frame(deadline);
        stream.send_frame(empty_response(state.request, 0, true), deadline);
    });
    const auto result = app::query_server(example_question(), server.endpoint(),
                                         app::TransportMode::Tcp, 1500ms, query_id);
    worker.join();
    check_worker(state);
    REQUIRE(result.has_value());
    CHECK(result->response.header.truncated());
    REQUIRE(result->attempts.size() == 1);
    CHECK_FALSE(server.pending(net::Deadline::after(30ms)));
    const auto extra = net::receive_datagram(udp.socket(), net::Deadline::after(30ms));
    REQUIRE_FALSE(extra.has_value());
    CHECK(extra.error().code == net::NetworkErrorCode::TimedOut);
}

TEST_CASE("Invalid query inputs fail before opening a TCP connection", "[query][tcp]") {
    TcpServer server;
    const auto check_error = [&](const auto& result, app::QueryErrorCode code) {
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == code);
        CHECK(result.error().attempts.empty());
    };
    check_error(app::query_server(example_question(), server.endpoint(),
                                  static_cast<app::TransportMode>(99), 1500ms, query_id),
                app::QueryErrorCode::InvalidMode);
    check_error(app::query_server(example_question(), server.endpoint(),
                                  app::TransportMode::Tcp, 99ms, query_id),
                app::QueryErrorCode::InvalidTimeout);
    auto endpoint = server.endpoint();
    endpoint.port = 0;
    check_error(app::query_server(example_question(), endpoint,
                                  app::TransportMode::Tcp, 1500ms, query_id),
                app::QueryErrorCode::InvalidEndpoint);
    auto question = example_question();
    question.name.labels.push_back("");
    check_error(app::query_server(question, server.endpoint(),
                                  app::TransportMode::Tcp, 1500ms, query_id),
                app::QueryErrorCode::Encode);
    CHECK_FALSE(server.pending(net::Deadline::after(30ms)));
}
