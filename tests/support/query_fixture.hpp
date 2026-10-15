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

inline dns::DnsQuestion example_question(std::uint16_t type = 1) {
    return {dns::DnsName{{"example", "com"}}, type, 1};
}

inline dns::Packet empty_response(const dns::Packet& query,
                                  unsigned int rcode = 0, bool truncated = false) {
    auto response = query;
    response.at(2) = truncated ? std::byte{0x83} : std::byte{0x81};
    response.at(3) = static_cast<std::byte>(0x80U | rcode);
    return response;
}

enum class AnswerKind { A, Aaaa, Cname };

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

template <typename Function>
std::jthread start_worker(WorkerState& state, Function function) {
    return std::jthread{[&state, function = std::move(function)](std::stop_token stop) {
        try {
            function(net::Deadline::after(3000ms), stop);
        } catch (...) {
            state.exception = std::current_exception();
        }
    }};
}

inline void check_worker(const WorkerState& state) {
    if (state.exception) {
        try {
            std::rethrow_exception(state.exception);
        } catch (const std::exception& error) {
            FAIL("local server failed: " << error.what());
        }
    }
    REQUIRE_FALSE(state.request.empty());
}

// Models deliberate network latency; stop requests end it promptly on test exit.
inline bool delay(std::stop_token stop, std::chrono::milliseconds duration) {
    std::mutex mutex;
    std::unique_lock lock{mutex};
    std::condition_variable_any condition;
    condition.wait_for(lock, stop, duration, [] { return false; });
    return !stop.stop_requested();
}

class UdpServer {
public:
    explicit UdpServer(net::Endpoint endpoint =
                          tcp_fixture_detail::loopback(net::IpFamily::V4, 0)) {
        auto opened = net::Socket::open(endpoint.family(), net::SocketTransport::Udp);
        if (!opened) {
            throw FixtureError("UDP server open", opened.error().system_code);
        }
        socket_ = std::move(*opened);
        const auto bound = net::bind_socket(socket_, endpoint);
        if (!bound) {
            throw FixtureError("UDP server bind", bound.error().system_code);
        }
        const auto local = net::local_endpoint(socket_);
        if (!local) {
            throw FixtureError("UDP server endpoint", local.error().system_code);
        }
        endpoint_ = *local;
    }

    [[nodiscard]] const net::Endpoint& endpoint() const noexcept { return endpoint_; }
    [[nodiscard]] const net::Socket& socket() const noexcept { return socket_; }

    [[nodiscard]] net::Datagram receive(const net::Deadline& deadline) const {
        auto received = net::receive_datagram(socket_, deadline);
        if (!received) {
            throw FixtureError("UDP server receive", received.error().system_code,
                received.error().code == net::NetworkErrorCode::TimedOut);
        }
        return std::move(*received);
    }

    void send(const net::Endpoint& destination, const dns::Packet& packet,
              const net::Deadline& deadline) const {
        const auto sent = net::send_datagram(socket_, destination, packet, deadline);
        if (!sent) {
            throw FixtureError("UDP server send", sent.error().system_code,
                sent.error().code == net::NetworkErrorCode::TimedOut);
        }
    }

private:
    net::Socket socket_;
    net::Endpoint endpoint_{};
};

inline void check_request(const dns::Packet& request, std::uint16_t type = 1) {
    // Fixed wire bytes independently check the request sent to the server.
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

} // namespace dnslab::test
