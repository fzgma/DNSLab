#include "app/udp_query.hpp"
#include "dns/byte_utils.hpp"
#include "dns/wire_codec.hpp"
#include "net/deadline.hpp"
#include "net/socket.hpp"
#include "net/udp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <stop_token>
#include <thread>
#include <utility>
#include <variant>

namespace {

using namespace dnslab;
using namespace std::chrono_literals;

constexpr std::uint16_t transaction_id = 0x1234;

struct BoundServer {
    net::Socket socket;
    net::Endpoint endpoint;
};

struct ServerState {
    dns::Packet query;
    std::optional<net::NetworkError> network_error;
    std::exception_ptr exception;
    std::size_t sent{};
};

/// 在指定地址族的回环临时端口创建 UDP 测试服务器。
BoundServer bind_loopback(net::IpFamily family = net::IpFamily::V4) {
    net::Endpoint endpoint;
    endpoint.port = 0;
    if (family == net::IpFamily::V4) {
        endpoint.address = net::Ipv4Address{
            std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1}};
    } else {
        net::Ipv6Address address{};
        address.back() = std::byte{1};
        endpoint.address = address;
    }

    auto socket = net::Socket::open(family, net::SocketTransport::Udp);
    REQUIRE(socket.has_value());
    const auto bound = net::bind_socket(*socket, endpoint);
    REQUIRE(bound.has_value());
    const auto local = net::local_endpoint(*socket);
    REQUIRE(local.has_value());
    REQUIRE(local->port != 0);
    return BoundServer{std::move(*socket), *local};
}

/// 启动一次有界 UDP 服务并把异常和原始请求交回主线程检查。
template <typename Handler>
std::jthread serve_once(const BoundServer& server, ServerState& state, Handler handler) {
    /// 接收一次请求后执行场景处理器，并捕获工作线程中的所有异常。
    return std::jthread{[&server, &state, handler = std::move(handler)](
                            std::stop_token stop) {
        try {
            const auto deadline = net::Deadline::after(2000ms);
            const auto request = net::receive_datagram(server.socket, deadline);
            if (!request) {
                state.network_error = request.error();
                return;
            }
            state.query = request->bytes;
            handler(*request, deadline, stop);
        } catch (...) {
            state.exception = std::current_exception();
        }
    }};
}

/// 发送 UDP 测试响应并记录底层错误和成功发送数量。
bool send_reply(const net::Socket& socket, const net::Endpoint& destination,
                const dns::Packet& packet, const net::Deadline& deadline,
                ServerState& state) {
    const auto sent = net::send_datagram(socket, destination, packet, deadline);
    if (!sent) {
        state.network_error = sent.error();
        return false;
    }
    ++state.sent;
    return true;
}

/// 在主线程验证 UDP 测试服务器收到请求且未发生异常。
void check_server(const ServerState& state) {
    REQUIRE_FALSE(static_cast<bool>(state.exception));
    if (state.network_error) {
        INFO("服务器操作阶段 " << static_cast<int>(state.network_error->operation)
             << "，系统错误码 " << state.network_error->system_code
             << "，错误类别 " << static_cast<int>(state.network_error->code));
        FAIL("本地 UDP 服务器失败");
    }
    REQUIRE_FALSE(state.query.empty());
}

/// 构造指定记录类型的固定域名查询。
dns::DnsQuestion example_question(std::uint16_t type = 1) {
    return dns::DnsQuestion{dns::DnsName{{"example", "com"}}, type, 1};
}

/// 在原查询上设置响应标志，构造没有回答的有效 DNS 响应。
dns::Packet empty_response(const dns::Packet& query) {
    auto response = query;
    response.at(2) = std::byte{0x81}; // 设置 QR 和 RD 标志。
    response.at(3) = std::byte{0x80}; // 设置 RA 标志及 NOERROR 响应码。
    return response;
}

enum class AnswerKind { A, Aaaa, Cname };

/// 用固定报文字节构造包含 A、AAAA 或 CNAME 的响应。
dns::Packet response_with_answer(const dns::Packet& query, AnswerKind kind) {
    auto response = empty_response(query);
    response[7] = std::byte{1};
    response.insert(response.end(), {std::byte{0xC0}, std::byte{0x0C}});
    switch (kind) {
    case AnswerKind::A:
        response.insert(response.end(), {
            std::byte{0}, std::byte{1}, std::byte{0}, std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{60},
            std::byte{0}, std::byte{4},
            std::byte{192}, std::byte{0}, std::byte{2}, std::byte{10}});
        break;
    case AnswerKind::Aaaa:
        response.insert(response.end(), {
            std::byte{0}, std::byte{28}, std::byte{0}, std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{60},
            std::byte{0}, std::byte{16},
            std::byte{0x20}, std::byte{0x01}, std::byte{0x0D}, std::byte{0xB8},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}});
        break;
    case AnswerKind::Cname:
        response.insert(response.end(), {
            std::byte{0}, std::byte{5}, std::byte{0}, std::byte{1},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{60},
            std::byte{0}, std::byte{8},
            std::byte{5}, std::byte{0x61}, std::byte{0x6C}, std::byte{0x69},
            std::byte{0x61}, std::byte{0x73}, std::byte{0xC0}, std::byte{0x0C}});
        break;
    }
    return response;
}

enum class Rejection { Id, Qr, Opcode, Count, Name, Type, Class, Malformed };

/// 按指定拒绝原因改写响应，以独立验证响应匹配逻辑。
dns::Packet rejected_response(const dns::Packet& query, Rejection rejection) {
    auto response = empty_response(query);
    switch (rejection) {
    case Rejection::Id:
        response[1] ^= std::byte{1};
        break;
    case Rejection::Qr:
        response[2] &= std::byte{0x7F};
        break;
    case Rejection::Opcode:
        response[2] |= std::byte{0x08};
        break;
    case Rejection::Count:
        response[5] = std::byte{0};
        response.resize(12);
        break;
    case Rejection::Name:
        response[13] = std::byte{0x78};
        break;
    case Rejection::Type:
        response[response.size() - 3] = std::byte{28};
        break;
    case Rejection::Class:
        response.back() = std::byte{3};
        break;
    case Rejection::Malformed:
        return dns::Packet{std::byte{0}};
    }
    return response;
}

/// 完成一次本地 UDP 查询并核对问题、回答、耗时及忽略数量。
void check_query_answer(net::IpFamily family, std::uint16_t type, AnswerKind answer_kind) {
    CAPTURE(type, static_cast<int>(family), static_cast<int>(answer_kind));
    const auto server = bind_loopback(family);
    const auto question = example_question(type);
    ServerState state;
    /// 发送指定回答类型的响应供 UDP 查询结果校验。
    auto worker = serve_once(server, state, [&](const net::Datagram& request,
                             const net::Deadline& deadline, std::stop_token) {
        send_reply(server.socket, request.sender,
                   response_with_answer(request.bytes, answer_kind), deadline, state);
    });

    const auto result = app::query_udp(question, server.endpoint, 1000ms, transaction_id);
    worker.join();
    check_server(state);
    REQUIRE(result.has_value());
    CHECK(result->server == server.endpoint);
    CHECK(result->question.name.labels == question.name.labels);
    CHECK(result->question.type == question.type);
    CHECK(result->question.qclass == question.qclass);
    CHECK(result->transaction_id == transaction_id);
    CHECK(result->response.header.id == transaction_id);
    CHECK(result->elapsed >= 0us);
    CHECK(result->elapsed < 1000ms);
    CHECK(result->ignored_datagrams == 0);
    REQUIRE(result->response.answers.size() == 1);
    const auto& answer = result->response.answers.front();
    CHECK(answer.owner.labels == question.name.labels);
    CHECK(answer.ttl == 60);
    CHECK(answer.rr_class == 1);

    if (answer_kind == AnswerKind::A) {
        const auto* data = std::get_if<dns::AData>(&answer.rdata);
        REQUIRE(data != nullptr);
        const std::array expected{
            std::byte{192}, std::byte{0}, std::byte{2}, std::byte{10}};
        CHECK(data->address == expected);
    } else if (answer_kind == AnswerKind::Aaaa) {
        const auto* data = std::get_if<dns::AaaaData>(&answer.rdata);
        REQUIRE(data != nullptr);
        const std::array expected{
            std::byte{0x20}, std::byte{1}, std::byte{0x0D}, std::byte{0xB8},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
        CHECK(data->address == expected);
    } else {
        const auto* data = std::get_if<dns::NameData>(&answer.rdata);
        REQUIRE(data != nullptr);
        const dns::DnsName expected{{"alias", "example", "com"}};
        CHECK(data->name.labels == expected.labels);
    }
    CHECK(result->response.authority.empty());
    CHECK(result->response.additional.empty());
}

TEST_CASE("本地 IPv4 UDP 查询保留 A、AAAA 和 CNAME 回答",
          "[udp_query][integration]") {
    check_query_answer(net::IpFamily::V4, 1, AnswerKind::A);
    check_query_answer(net::IpFamily::V4, 28, AnswerKind::Aaaa);
    check_query_answer(net::IpFamily::V4, 1, AnswerKind::Cname);
}

TEST_CASE("本地 IPv6 UDP 查询保留 AAAA 回答",
          "[udp_query][integration]") {
    check_query_answer(net::IpFamily::V6, 28, AnswerKind::Aaaa);
}

TEST_CASE("UDP 接受空回答、DNS 错误响应码和 TC 标志",
          "[udp_query][integration]") {
    struct Sample {
        std::uint8_t rcode;
        bool truncated;
    };
    constexpr std::array samples{
        Sample{0, false}, Sample{2, false}, Sample{3, false}, Sample{0, true}};

    for (const auto sample : samples) {
        CAPTURE(sample.rcode, sample.truncated);
        const auto server = bind_loopback();
        ServerState state;
        /// 返回当前样本的响应码与截断状态。
        auto worker = serve_once(server, state, [&](const net::Datagram& request,
                                 const net::Deadline& deadline, std::stop_token) {
            auto response = empty_response(request.bytes);
            response[3] |= static_cast<std::byte>(sample.rcode);
            if (sample.truncated) {
                response[2] |= std::byte{0x02};
            }
            send_reply(server.socket, request.sender, response, deadline, state);
        });
        const auto result = app::query_udp(example_question(), server.endpoint,
                                            1000ms, transaction_id);
        worker.join();
        check_server(state);
        REQUIRE(result.has_value());
        CHECK(result->response.header.rcode() == sample.rcode);
        CHECK(result->response.header.truncated() == sample.truncated);
        CHECK(result->response.answers.empty());
        CHECK(state.sent == 1);
    }
}

TEST_CASE("UDP 自动生成事务 ID 并匹配原样返回的响应",
          "[udp_query][integration]") {
    const auto server = bind_loopback();
    ServerState state;
    /// 原样使用请求事务 ID 返回有效响应。
    auto worker = serve_once(server, state, [&](const net::Datagram& request,
                             const net::Deadline& deadline, std::stop_token) {
        send_reply(server.socket, request.sender, empty_response(request.bytes), deadline, state);
    });
    const auto result = app::query_udp(example_question(), server.endpoint);
    worker.join();
    check_server(state);
    REQUIRE(result.has_value());
    const auto sent_id = dns::read_u16_be(state.query, 0);
    REQUIRE(sent_id.has_value());
    CHECK(result->transaction_id == *sent_id);
    CHECK(result->response.header.id == *sent_id);
}

TEST_CASE("UDP 在畸形和不匹配响应后继续等待",
          "[udp_query][integration]") {
    for (const auto rejection : {Rejection::Id, Rejection::Qr, Rejection::Opcode,
                                 Rejection::Count, Rejection::Name, Rejection::Type,
                                 Rejection::Class, Rejection::Malformed}) {
        CAPTURE(static_cast<int>(rejection));
        const auto server = bind_loopback();
        ServerState state;
        /// 先发送被拒绝的响应，再发送有效响应以验证继续接收。
        auto worker = serve_once(server, state, [&](const net::Datagram& request,
                                 const net::Deadline& deadline, std::stop_token) {
            if (send_reply(server.socket, request.sender,
                           rejected_response(request.bytes, rejection), deadline, state)) {
                send_reply(server.socket, request.sender,
                           empty_response(request.bytes), deadline, state);
            }
        });
        const auto question = example_question();
        const auto result = app::query_udp(question, server.endpoint, 1000ms, transaction_id);
        worker.join();
        check_server(state);
        REQUIRE(result.has_value());
        CHECK(app::validate_response(result->response, question, transaction_id).has_value());
        CHECK(result->ignored_datagrams == 1);
        CHECK(state.sent == 2);
    }
}

TEST_CASE("UDP 在解析报文前忽略不同来源",
          "[udp_query][integration]") {
    for (const bool send_valid_afterward : {false, true}) {
        CAPTURE(send_valid_afterward);
        const auto server = bind_loopback();
        const auto stranger = bind_loopback();
        REQUIRE(server.endpoint != stranger.endpoint);
        ServerState state;
        /// 从其他来源发送数据，并按场景决定是否随后发送有效响应。
        auto worker = serve_once(server, state, [&](const net::Datagram& request,
                                 const net::Deadline& deadline, std::stop_token) {
            const dns::Packet malformed{std::byte{0}};
            if (send_reply(stranger.socket, request.sender, malformed, deadline, state) &&
                send_valid_afterward) {
                send_reply(server.socket, request.sender,
                           empty_response(request.bytes), deadline, state);
            }
        });
        const auto result = app::query_udp(example_question(), server.endpoint,
                                            200ms, transaction_id);
        worker.join();
        check_server(state);
        if (send_valid_afterward) {
            REQUIRE(result.has_value());
            CHECK(result->ignored_datagrams == 1);
        } else {
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == app::UdpQueryErrorCode::Timeout);
            CHECK(std::holds_alternative<std::monostate>(result.error().detail));
            CHECK(result.error().ignored_datagrams == 1);
        }
    }
}

TEST_CASE("UDP 报告指定服务器最近一次无效响应",
          "[udp_query][integration]") {
    for (const bool malformed_last : {false, true}) {
        CAPTURE(malformed_last);
        const auto server = bind_loopback();
        ServerState state;
        /// 按场景顺序发送畸形或不匹配响应以验证最近拒绝原因。
        auto worker = serve_once(server, state, [&](const net::Datagram& request,
                                 const net::Deadline& deadline, std::stop_token) {
            const auto first = malformed_last ? Rejection::Id : Rejection::Malformed;
            const auto last = malformed_last ? Rejection::Malformed : Rejection::Id;
            if (send_reply(server.socket, request.sender,
                           rejected_response(request.bytes, first), deadline, state)) {
                send_reply(server.socket, request.sender,
                           rejected_response(request.bytes, last), deadline, state);
            }
        });
        const auto result = app::query_udp(example_question(), server.endpoint,
                                            100ms, transaction_id);
        worker.join();
        check_server(state);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == app::UdpQueryErrorCode::InvalidResponse);
        CHECK(result.error().ignored_datagrams == 2);
        if (malformed_last) {
            const auto* error = std::get_if<dns::DnsParseError>(&result.error().detail);
            REQUIRE(error != nullptr);
            CHECK(error->code == dns::DnsParseErrorCode::PacketTooShort);
            CHECK(error->offset == 1);
        } else {
            const auto* error = std::get_if<app::ResponseMismatch>(&result.error().detail);
            REQUIRE(error != nullptr);
            CHECK(*error == app::ResponseMismatch::TransactionId);
        }
    }
}

TEST_CASE("本地 UDP 服务器无响应时单次查询超时",
          "[udp_query][integration]") {
    const auto server = bind_loopback();
    const auto started_at = net::Deadline::Clock::now();
    const auto result = app::query_udp(example_question(), server.endpoint,
                                       100ms, transaction_id);
    const auto elapsed = net::Deadline::Clock::now() - started_at;

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == app::UdpQueryErrorCode::Timeout);
    CHECK(result.error().ignored_datagrams == 0);
    CHECK(elapsed >= 100ms);
    CHECK(elapsed < 1000ms);
    const auto request = net::receive_datagram(server.socket, net::Deadline::after(100ms));
    REQUIRE(request.has_value());
    const auto parsed = dns::parse_message(request->bytes);
    REQUIRE(parsed.has_value());
    CHECK_FALSE(parsed->header.is_response());
    CHECK(parsed->header.id == transaction_id);

    const auto duplicate = net::receive_datagram(server.socket, net::Deadline::after(30ms));
    REQUIRE_FALSE(duplicate.has_value());
    CHECK(duplicate.error().code == net::NetworkErrorCode::TimedOut);
}

TEST_CASE("连续无关 UDP 响应不能延长查询预算",
          "[udp_query][integration]") {
    const auto server = bind_loopback();
    ServerState state;
    /// 持续发送事务不匹配的响应，验证查询截止时间不会延长。
    auto worker = serve_once(server, state, [&](const net::Datagram& request,
                             const net::Deadline& deadline, std::stop_token stop) {
        const auto response = rejected_response(request.bytes, Rejection::Id);
        while (!stop.stop_requested() && !deadline.expired()) {
            const auto sent = net::send_datagram(server.socket, request.sender, response, deadline);
            if (!sent) {
                if (sent.error().code != net::NetworkErrorCode::TimedOut) {
                    state.network_error = sent.error();
                }
                break;
            }
            ++state.sent;
            std::this_thread::yield();
        }
    });

    const auto started_at = net::Deadline::Clock::now();
    const auto result = app::query_udp(example_question(), server.endpoint,
                                       200ms, transaction_id);
    const auto elapsed = net::Deadline::Clock::now() - started_at;
    worker.request_stop();
    worker.join();
    check_server(state);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == app::UdpQueryErrorCode::InvalidResponse);
    CHECK(result.error().ignored_datagrams > 1);
    CHECK(elapsed >= 200ms);
    CHECK(elapsed < 1000ms); // 若每次响应都重置预算，查询将超过发送线程的两秒时限。
}

TEST_CASE("无效 UDP 查询输入在发包前失败",
          "[udp_query][integration]") {
    const auto server = bind_loopback();
    for (const auto budget : {99ms, 30001ms}) {
        const auto result = app::query_udp(example_question(), server.endpoint,
                                            budget, transaction_id);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == app::UdpQueryErrorCode::InvalidTimeout);
    }

    auto invalid_endpoint = server.endpoint;
    invalid_endpoint.port = 0;
    const auto invalid_server = app::query_udp(example_question(), invalid_endpoint,
                                                100ms, transaction_id);
    REQUIRE_FALSE(invalid_server.has_value());
    CHECK(invalid_server.error().code == app::UdpQueryErrorCode::InvalidEndpoint);

    struct Sample {
        dns::DnsQuestion question;
        dns::DnsEncodeErrorCode code;
        std::size_t label_index;
    };
    const std::array samples{
        Sample{dns::DnsQuestion{dns::DnsName{{"ok", ""}}, 1, 1},
               dns::DnsEncodeErrorCode::EmptyLabel, 1},
        Sample{dns::DnsQuestion{dns::DnsName{{"example", "com"}}, 5, 1},
               dns::DnsEncodeErrorCode::UnsupportedQueryType, 0},
        Sample{dns::DnsQuestion{dns::DnsName{{"example", "com"}}, 1, 3},
               dns::DnsEncodeErrorCode::UnsupportedQueryClass, 0},
    };
    for (const auto& sample : samples) {
        const auto result = app::query_udp(sample.question, server.endpoint,
                                            100ms, transaction_id);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == app::UdpQueryErrorCode::Encode);
        const auto* error = std::get_if<dns::DnsEncodeError>(&result.error().detail);
        REQUIRE(error != nullptr);
        CHECK(error->code == sample.code);
        CHECK(error->label_index == sample.label_index);
    }

    const auto unexpected = net::receive_datagram(server.socket, net::Deadline::after(30ms));
    REQUIRE_FALSE(unexpected.has_value());
    CHECK(unexpected.error().code == net::NetworkErrorCode::TimedOut);
}

} // 匿名命名空间
