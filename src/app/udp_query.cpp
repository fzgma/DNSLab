#include "app/udp_query.hpp"

#include "app/query.hpp"

#include <utility>
#include <type_traits>

namespace dnslab::app {
namespace {

/// 将统一查询错误映射为兼容的 UDP 查询错误类别。
UdpQueryErrorCode udp_error_code(QueryErrorCode code) noexcept {
    switch (code) {
    case QueryErrorCode::InvalidTimeout:
        return UdpQueryErrorCode::InvalidTimeout;
    case QueryErrorCode::InvalidEndpoint:
        return UdpQueryErrorCode::InvalidEndpoint;
    case QueryErrorCode::Encode:
        return UdpQueryErrorCode::Encode;
    case QueryErrorCode::IdGeneration:
        return UdpQueryErrorCode::IdGeneration;
    case QueryErrorCode::Network:
        return UdpQueryErrorCode::Network;
    case QueryErrorCode::Timeout:
        return UdpQueryErrorCode::Timeout;
    case QueryErrorCode::InvalidResponse:
        return UdpQueryErrorCode::InvalidResponse;
    case QueryErrorCode::InvalidMode:
        // 下方唯一调用者始终传入合法的 UDP 模式，此分支不可达。
        std::unreachable();
    }
    std::unreachable();
}

} // 匿名命名空间

/// 复用统一查询流程并转换结果，保持原 UDP 公共接口的错误和计数语义。
std::expected<UdpQueryResult, UdpQueryError>
query_udp(const dns::DnsQuestion& question, const net::Endpoint& server,
          std::chrono::milliseconds budget,
          std::optional<std::uint16_t> transaction_id) {
    auto result = query_server(question, server, TransportMode::Udp, budget, transaction_id);
    if (!result) {
        const auto& error = result.error();
        /// 保留普通查询的错误详情，并排除显式 UDP 不可能进入的加密传输错误。
        const auto detail = std::visit([](const auto& value) -> UdpQueryErrorDetail {
            if constexpr (std::is_same_v<std::decay_t<decltype(value)>, net::EncryptedError>) {
                // 显式 UDP 查询不会进入加密传输，此分支不可达。
                std::unreachable();
            } else {
                return value;
            }
        }, error.detail);
        return std::unexpected(UdpQueryError{
            udp_error_code(error.code), detail, error.ignored_messages});
    }
    return UdpQueryResult{
        std::move(result->server), std::move(result->question), result->transaction_id,
        std::move(result->response), result->elapsed, result->ignored_messages};
}

} // 命名空间 dnslab::app
