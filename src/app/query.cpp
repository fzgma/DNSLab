#include "app/query.hpp"

#include "dns/wire_codec.hpp"
#include "net/deadline.hpp"
#include "net/socket.hpp"
#include "net/tcp.hpp"
#include "net/udp.hpp"

#include <limits>
#include <random>
#include <utility>

namespace dnslab::app {
namespace {

using Clock = net::Deadline::Clock;

struct QueryContext {
    const dns::DnsQuestion& question;
    const net::Endpoint& server;
    dns::Packet packet;
    std::uint16_t transaction_id;
    net::Deadline deadline;
};

/// 计算从指定单调时钟起点至今的微秒耗时。
std::chrono::microseconds elapsed_since(Clock::time_point started_at) {
    return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started_at);
}

/// 区分完全未获响应的超时与收到无效响应后耗尽预算。
QueryFailure timeout_failure(const QueryErrorDetail& last_rejection) {
    if (!std::holds_alternative<std::monostate>(last_rejection)) {
        return {QueryErrorCode::InvalidResponse, last_rejection};
    }
    return {QueryErrorCode::Timeout};
}

/// 将网络错误映射为查询失败，同时保留底层原因和最近一次响应拒绝详情。
QueryFailure network_failure(net::NetworkError error,
                             const QueryErrorDetail& last_rejection = {}) {
    if (error.code == net::NetworkErrorCode::TimedOut) {
        return timeout_failure(last_rejection);
    }
    if (error.code == net::NetworkErrorCode::InvalidMessageLength) {
        return {QueryErrorCode::InvalidResponse, error};
    }
    // 连接关闭、连接失败和其他收发错误保留原始原因，不被此前的畸形或不匹配响应覆盖。
    return {QueryErrorCode::Network, error};
}

/// 在共享截止时间内完成一次传输，并记录响应或失败和忽略消息数量。
QueryAttempt run_attempt(const QueryContext& context, QueryTransport transport) {
    const auto started_at = Clock::now();
    std::size_t ignored = 0;
    QueryErrorDetail last_rejection;
    /// 为当前尝试生成包含耗时与已忽略消息数的失败记录。
    const auto failed = [&](QueryFailure failure) {
        return QueryAttempt{transport, elapsed_since(started_at),
                            std::unexpected(std::move(failure)), ignored};
    };

    if (context.deadline.expired()) {
        return failed(timeout_failure(last_rejection));
    }
    const auto socket_transport = transport == QueryTransport::Udp
        ? net::SocketTransport::Udp : net::SocketTransport::Tcp;
    auto socket = net::Socket::open(context.server.family(), socket_transport);
    if (!socket) {
        return failed(network_failure(socket.error()));
    }
    if (transport == QueryTransport::Tcp) {
        const auto connected = net::connect_socket(*socket, context.server, context.deadline);
        if (!connected) {
            return failed(network_failure(connected.error()));
        }
    }

    const auto sent = transport == QueryTransport::Udp
        ? net::send_datagram(*socket, context.server, context.packet, context.deadline)
        : net::send_tcp_message(*socket, context.packet, context.deadline);
    if (!sent) {
        return failed(network_failure(sent.error()));
    }

    for (;;) {
        if (context.deadline.expired()) {
            return failed(timeout_failure(last_rejection));
        }

        dns::Packet bytes;
        if (transport == QueryTransport::Udp) {
            auto received = net::receive_datagram(*socket, context.deadline);
            if (!received) {
                return failed(network_failure(received.error(), last_rejection));
            }
            // 先校验来源，避免把其他端点的数据计入目标服务器的无效响应。
            if (received->sender != context.server) {
                ++ignored;
                continue;
            }
            bytes = std::move(received->bytes);
        } else {
            auto received = net::receive_tcp_message(*socket, context.deadline);
            if (!received) {
                return failed(network_failure(received.error(), last_rejection));
            }
            bytes = std::move(*received);
        }

        // 只有完整解析且事务匹配的消息才可成功；忽略坏消息仍继续使用同一截止时间。
        auto response = dns::parse_message(bytes);
        if (!response) {
            last_rejection = response.error();
            ++ignored;
            continue;
        }
        const auto matched = validate_response(*response, context.question,
                                               context.transaction_id);
        if (!matched) {
            last_rejection = matched.error();
            ++ignored;
            continue;
        }

        const auto finished_at = Clock::now();
        if (context.deadline.expired(finished_at)) {
            return failed(timeout_failure(last_rejection));
        }
        return QueryAttempt{
            transport,
            std::chrono::duration_cast<std::chrono::microseconds>(finished_at - started_at),
            std::move(*response), ignored};
    }
}

} // 匿名命名空间

/// 校验请求并编排普通 DNS 查询，自动回退时沿用原报文和剩余预算。
std::expected<QueryResult, QueryError>
query_server(const dns::DnsQuestion& question, const net::Endpoint& server,
             TransportMode mode, std::chrono::milliseconds budget,
             std::optional<std::uint16_t> transaction_id) {
    switch (mode) {
    case TransportMode::Auto:
    case TransportMode::Udp:
    case TransportMode::Tcp:
        break;
    default:
        return std::unexpected(QueryError{QueryErrorCode::InvalidMode});
    }
    if (budget < std::chrono::milliseconds{100} ||
        budget > std::chrono::milliseconds{30000}) {
        return std::unexpected(QueryError{QueryErrorCode::InvalidTimeout});
    }
    if (server.port == 0) {
        return std::unexpected(QueryError{QueryErrorCode::InvalidEndpoint});
    }

    const auto started_at = Clock::now();
    const auto deadline = net::Deadline::after(budget, started_at);
    auto id = transaction_id.value_or(0);
    auto packet = dns::encode_query(question, id);
    if (!packet) {
        return std::unexpected(QueryError{
            QueryErrorCode::Encode, packet.error(), elapsed_since(started_at)});
    }

    if (!transaction_id) {
        try {
            std::random_device random;
            std::uniform_int_distribution<std::uint32_t> distribution{
                0, std::numeric_limits<std::uint16_t>::max()};
            id = static_cast<std::uint16_t>(distribution(random));
        } catch (...) {
            return std::unexpected(QueryError{
                QueryErrorCode::IdGeneration, {}, elapsed_since(started_at)});
        }
        // UDP 和 TCP 共用已经校验的查询报文；自动生成 ID 时只替换两个事务 ID 字节。
        (*packet)[0] = static_cast<std::byte>(id >> 8);
        (*packet)[1] = static_cast<std::byte>(id & 0xFFU);
    }
    if (deadline.expired()) {
        return std::unexpected(QueryError{
            QueryErrorCode::Timeout, {}, elapsed_since(started_at)});
    }

    const QueryContext context{question, server, std::move(*packet), id, deadline};
    std::vector<QueryAttempt> attempts;
    attempts.reserve(mode == TransportMode::Auto ? 2U : 1U);
    attempts.push_back(run_attempt(context, mode == TransportMode::Tcp
        ? QueryTransport::Tcp : QueryTransport::Udp));
    // 仅匹配的截断 UDP 响应触发一次 TCP 回退，UDP 超时或 TCP 再次截断都不继续回退。
    if (mode == TransportMode::Auto && attempts.front().outcome &&
        attempts.front().outcome->header.truncated()) {
        attempts.push_back(run_attempt(context, QueryTransport::Tcp));
    }

    std::size_t ignored = 0;
    for (const auto& attempt : attempts) {
        ignored += attempt.ignored_messages;
    }
    const auto& final_attempt = attempts.back();
    if (!final_attempt.outcome) {
        const auto& failure = final_attempt.outcome.error();
        return std::unexpected(QueryError{
            failure.code, failure.detail, elapsed_since(started_at), ignored,
            std::move(attempts)});
    }
    return QueryResult{
        server, question, id, final_attempt.transport, *final_attempt.outcome,
        elapsed_since(started_at), ignored, std::move(attempts)};
}

} // 命名空间 dnslab::app
