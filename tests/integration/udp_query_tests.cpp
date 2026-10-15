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

template <typename Handler>
std::jthread serve_once(const BoundServer& server, ServerState& state, Handler handler) {
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

void check_server(const ServerState& state) {
    REQUIRE_FALSE(static_cast<bool>(state.exception));
    if (state.network_error) {
        INFO("server operation " << static_cast<int>(state.network_error->operation)
             << ", system error " << state.network_error->system_code
             << ", code " << static_cast<int>(state.network_error->code));
        FAIL("local UDP server failed");
    }
    REQUIRE_FALSE(state.query.empty());
}

dns::DnsQuestion example_question(std::uint16_t type = 1) {
    return dns::DnsQuestion{dns::DnsName{{"example", "com"}}, type, 1};
}

dns::Packet empty_response(const dns::Packet& query) {
    auto response = query;
    response.at(2) = std::byte{0x81}; // QR and RD.
    response.at(3) = std::byte{0x80}; // RA, NOERROR.
    return response;
}

enum class AnswerKind { A, Aaaa, Cname };

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

void check_query_answer(net::IpFamily family, std::uint16_t type, AnswerKind answer_kind) {
    CAPTURE(type, static_cast<int>(family), static_cast<int>(answer_kind));
    const auto server = bind_loopback(family);
    const auto question = example_question(type);
    ServerState state;
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

TEST_CASE("Local IPv4 UDP queries preserve A AAAA and CNAME answers",
          "[udp_query][integration]") {
    check_query_answer(net::IpFamily::V4, 1, AnswerKind::A);
    check_query_answer(net::IpFamily::V4, 28, AnswerKind::Aaaa);
    check_query_answer(net::IpFamily::V4, 1, AnswerKind::Cname);
}

TEST_CASE("Local IPv6 UDP queries preserve AAAA answers",
          "[udp_query][integration]") {
    check_query_answer(net::IpFamily::V6, 28, AnswerKind::Aaaa);
}

TEST_CASE("UDP accepts empty answers DNS error codes and the TC flag",
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

TEST_CASE("UDP can generate a transaction ID and match the echoed response",
          "[udp_query][integration]") {
    const auto server = bind_loopback();
    ServerState state;
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

TEST_CASE("UDP keeps waiting after malformed and mismatched replies",
          "[udp_query][integration]") {
    for (const auto rejection : {Rejection::Id, Rejection::Qr, Rejection::Opcode,
                                 Rejection::Count, Rejection::Name, Rejection::Type,
                                 Rejection::Class, Rejection::Malformed}) {
        CAPTURE(static_cast<int>(rejection));
        const auto server = bind_loopback();
        ServerState state;
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

TEST_CASE("UDP ignores a different source before parsing its packet",
          "[udp_query][integration]") {
    for (const bool send_valid_afterward : {false, true}) {
        CAPTURE(send_valid_afterward);
        const auto server = bind_loopback();
        const auto stranger = bind_loopback();
        REQUIRE(server.endpoint != stranger.endpoint);
        ServerState state;
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

TEST_CASE("UDP reports the latest bad response from the requested server",
          "[udp_query][integration]") {
    for (const bool malformed_last : {false, true}) {
        CAPTURE(malformed_last);
        const auto server = bind_loopback();
        ServerState state;
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

TEST_CASE("A silent local UDP server times out after a single query",
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

TEST_CASE("Continuous unrelated UDP replies cannot renew the query budget",
          "[udp_query][integration]") {
    const auto server = bind_loopback();
    ServerState state;
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
    CHECK(elapsed < 1000ms); // A renewed budget would outlive the two-second sender.
}

TEST_CASE("Invalid UDP query inputs fail before sending a packet",
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

} // namespace
