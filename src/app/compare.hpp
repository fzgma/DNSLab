#pragma once

#include "app/query.hpp"

#include <chrono>
#include <cstddef>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace dnslab::app {

enum class CompareErrorCode {
    TooFewServers,
    DuplicateEndpoint,
    InvalidMode,
    InvalidTimeout,
    InvalidEndpoint,
    Encode,
};

struct CompareError {
    CompareErrorCode code;
    std::optional<std::size_t> input_index{};
    std::optional<std::size_t> first_duplicate_index{};
    std::optional<dns::DnsEncodeError> encode_error{};
};

struct CompareEntry {
    net::Endpoint server;
    std::expected<QueryResult, QueryError> outcome;
};

struct CompareResult {
    dns::DnsQuestion question;
    TransportMode mode;
    std::vector<CompareEntry> entries;
    std::chrono::microseconds elapsed;
};

struct ResponseDifferences {
    bool rcode{};
    bool flags{}; // 标志差异不重复包含低四位 RCODE。
    bool answers{};
    bool authority{};
    bool additional{};
    bool ttl{};

    /// 判断是否存在任意响应差异。
    [[nodiscard]] bool any() const noexcept;
};

/// 全量预检后按输入顺序串行查询，每台使用独立预算且单台失败不取消后续查询。
[[nodiscard]] std::expected<CompareResult, CompareError>
compare_servers(const dns::DnsQuestion& question, std::span<const net::Endpoint> servers,
                TransportMode mode = TransportMode::Auto,
                std::chrono::milliseconds budget = std::chrono::milliseconds{1500});

/// 比较同一问题的已验证响应，忽略事务 ID、记录顺序和名称 ASCII 大小写，保留记录重复次数。
// 三个记录区的差异不包含 TTL；同身份记录抵消相同 TTL 实例后，两侧仍有剩余时标记 TTL 差异。
[[nodiscard]] ResponseDifferences
compare_responses(const dns::DnsMessage& first, const dns::DnsMessage& second);

/// 仅比较两项成功查询的响应，任意一项失败时返回空值而非空答案。
[[nodiscard]] std::optional<ResponseDifferences>
compare_responses(const CompareEntry& first, const CompareEntry& second);

} // 命名空间 dnslab::app
