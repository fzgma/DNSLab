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

// DoH defaults to ID zero; DoT generates an ID unless one is supplied.
// One exchange is performed. Invalid responses fail without plaintext fallback.
[[nodiscard]] std::expected<EncryptedQueryResult, QueryError>
query_encrypted(const dns::DnsQuestion& question, const net::EncryptedEndpoint& server,
                std::chrono::milliseconds budget = std::chrono::milliseconds{1500},
                const net::TlsOptions& tls = {},
                std::optional<std::uint16_t> transaction_id = std::nullopt);

} // namespace dnslab::app
