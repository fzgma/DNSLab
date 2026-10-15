#pragma once

#include "app/query.hpp"
#include "net/encrypted_transport.hpp"

namespace dnslab::app {

struct EncryptedQueryResult {
    net::EncryptedEndpoint server;
    dns::DnsQuestion question;
    std::uint16_t transaction_id;
    QueryTransport transport;
    dns::DnsMessage response;
    std::chrono::microseconds elapsed;
    std::size_t ignored_messages{};
    std::vector<QueryAttempt> attempts{};
};

/// 在同一预算内执行一次严格验证证书的加密查询，响应无效时直接失败且不回退明文。
// DoH 默认事务 ID 为零；DoT 在调用者未指定时生成事务 ID。
[[nodiscard]] std::expected<EncryptedQueryResult, QueryError>
query_encrypted(const dns::DnsQuestion& question, const net::EncryptedEndpoint& server,
                std::chrono::milliseconds budget = std::chrono::milliseconds{1500},
                const net::TlsOptions& tls = {},
                std::optional<std::uint16_t> transaction_id = std::nullopt);

} // 命名空间 dnslab::app
