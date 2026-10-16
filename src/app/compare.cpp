#include "app/compare.hpp"

#include "dns/wire_codec.hpp"
#include "net/deadline.hpp"

#include <algorithm>
#include <compare>
#include <map>
#include <string>
#include <utility>

namespace dnslab::app {
namespace {

using Clock = net::Deadline::Clock;

/// 复制名称标签并仅折叠 ASCII 大写字母，保留原始字节和标签边界。
std::vector<std::string> normalized_labels(const dns::DnsName& name) {
    auto labels = name.labels;
    for (auto& label : labels) {
        for (char& value : label) {
            if (value >= 'A' && value <= 'Z') {
                value = static_cast<char>(value + ('a' - 'A'));
            }
        }
    }
    return labels;
}

struct RecordKey {
    std::vector<std::string> owner;
    std::uint16_t type;
    std::uint16_t rr_class;
    std::size_t data_kind;
    std::vector<std::vector<std::string>> names;
    std::vector<std::uint32_t> numbers;
    std::vector<dns::Packet> strings;
    dns::Packet bytes;

    /// 按规范化名称、类型、类别及完整数据排序，不把 TTL 纳入记录身份。
    auto operator<=>(const RecordKey&) const = default;
};

/// 将已解析记录转为稳定比较键，名称折叠大小写，数值和字符字符串边界完整保留。
RecordKey record_key(const dns::ResourceRecord& record) {
    RecordKey key{normalized_labels(record.owner), record.type, record.rr_class,
                  record.rdata.index(), {}, {}, {}, {}};
    if (const auto* address = std::get_if<dns::AData>(&record.rdata)) {
        key.bytes.assign(address->address.begin(), address->address.end());
    } else if (const auto* address6 = std::get_if<dns::AaaaData>(&record.rdata)) {
        key.bytes.assign(address6->address.begin(), address6->address.end());
    } else if (const auto* target = std::get_if<dns::NameData>(&record.rdata)) {
        key.names.push_back(normalized_labels(target->name));
    } else if (const auto* mx = std::get_if<dns::MxData>(&record.rdata)) {
        key.names.push_back(normalized_labels(mx->exchange));
        key.numbers.push_back(mx->preference);
    } else if (const auto* txt = std::get_if<dns::TxtData>(&record.rdata)) {
        // TXT 不是域名：大小写、字符串顺序和空段都属于记录内容。
        key.strings = txt->strings;
    } else if (const auto* soa = std::get_if<dns::SoaData>(&record.rdata)) {
        key.names = {normalized_labels(soa->mname), normalized_labels(soa->rname)};
        key.numbers = {soa->serial, soa->refresh, soa->retry, soa->expire, soa->minimum};
    } else {
        key.bytes = std::get<dns::OpaqueData>(record.rdata).bytes;
    }
    return key;
}

using RecordGroups = std::map<RecordKey, std::vector<std::uint32_t>>;

/// 按记录身份分组并排序 TTL，保留同一记录的全部重复实例。
RecordGroups group_records(std::span<const dns::ResourceRecord> records) {
    RecordGroups groups;
    for (const auto& record : records) {
        groups[record_key(record)].push_back(record.ttl);
    }
    for (auto& [key, values] : groups) {
        (void)key;
        std::ranges::sort(values);
    }
    return groups;
}

/// 抵消同身份且 TTL 相同的实例后，判断两边是否仍有可配对的不同 TTL。
bool ttl_differs(std::span<const std::uint32_t> first,
                 std::span<const std::uint32_t> second) {
    std::size_t left = 0;
    std::size_t right = 0;
    std::size_t equal = 0;
    while (left < first.size() && right < second.size()) {
        if (first[left] < second[right]) {
            ++left;
        } else if (second[right] < first[left]) {
            ++right;
        } else {
            ++left;
            ++right;
            ++equal;
        }
    }
    // 仅一边剩余意味着记录增删，不把重复次数变化误报为 TTL 变化。
    return equal < first.size() && equal < second.size();
}

/// 独立比较一个记录区的多重集合，并汇总可匹配记录的 TTL 差异。
bool section_differs(std::span<const dns::ResourceRecord> first,
                     std::span<const dns::ResourceRecord> second, bool& ttl) {
    const auto left = group_records(first);
    const auto right = group_records(second);
    bool different = left.size() != right.size();
    for (const auto& [key, values] : left) {
        const auto found = right.find(key);
        if (found == right.end()) {
            different = true;
            continue;
        }
        different = different || values.size() != found->second.size();
        ttl = ttl || ttl_differs(values, found->second);
    }
    return different;
}

/// 在任何网络操作前验证比较输入，保留首个无效端点或重复项的位置。
std::expected<void, CompareError>
validate_inputs(const dns::DnsQuestion& question, std::span<const net::Endpoint> servers,
                TransportMode mode, std::chrono::milliseconds budget) {
    if (servers.size() < 2) {
        return std::unexpected(CompareError{CompareErrorCode::TooFewServers});
    }
    switch (mode) {
    case TransportMode::Auto:
    case TransportMode::Udp:
    case TransportMode::Tcp:
        break;
    default:
        return std::unexpected(CompareError{CompareErrorCode::InvalidMode});
    }
    if (budget < std::chrono::milliseconds{100} || budget > std::chrono::milliseconds{30000}) {
        return std::unexpected(CompareError{CompareErrorCode::InvalidTimeout});
    }
    const auto encoded = dns::encode_query(question, 0);
    if (!encoded) {
        return std::unexpected(CompareError{
            CompareErrorCode::Encode, {}, {}, encoded.error()});
    }
    for (std::size_t index = 0; index < servers.size(); ++index) {
        if (servers[index].port == 0 || servers[index].address.valueless_by_exception()) {
            return std::unexpected(CompareError{CompareErrorCode::InvalidEndpoint, index});
        }
        for (std::size_t previous = 0; previous < index; ++previous) {
            if (servers[index] == servers[previous]) {
                return std::unexpected(CompareError{
                    CompareErrorCode::DuplicateEndpoint, index, previous});
            }
        }
    }
    return {};
}

} // 匿名命名空间

/// 汇总状态、各记录区和 TTL 的差异标志。
bool ResponseDifferences::any() const noexcept {
    return rcode || flags || answers || authority || additional || ttl;
}

/// 完成全部输入预检后串行查询各端点，每次调用独立创建其查询预算。
std::expected<CompareResult, CompareError>
compare_servers(const dns::DnsQuestion& question, std::span<const net::Endpoint> servers,
                TransportMode mode, std::chrono::milliseconds budget) {
    const auto validated = validate_inputs(question, servers, mode, budget);
    if (!validated) {
        return std::unexpected(validated.error());
    }
    const auto started_at = Clock::now();
    CompareResult result{question, mode, {}, {}};
    result.entries.reserve(servers.size());
    for (const auto& server : servers) {
        // 单台失败保存在该条目中；下一台仍从自己的查询起点获得完整预算。
        result.entries.push_back(CompareEntry{server, query_server(question, server, mode, budget)});
    }
    result.elapsed = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started_at);
    return result;
}

/// 分别比较响应码、其他标志和三个记录区，忽略事务 ID 与记录顺序。
ResponseDifferences compare_responses(const dns::DnsMessage& first, const dns::DnsMessage& second) {
    ResponseDifferences result;
    result.rcode = first.header.rcode() != second.header.rcode();
    result.flags = (first.header.flags & 0xfff0U) != (second.header.flags & 0xfff0U);
    result.answers = section_differs(first.answers, second.answers, result.ttl);
    result.authority = section_differs(first.authority, second.authority, result.ttl);
    result.additional = section_differs(first.additional, second.additional, result.ttl);
    return result;
}

/// 对失败条目返回不可比较状态，防止将查询失败等同于空响应。
std::optional<ResponseDifferences>
compare_responses(const CompareEntry& first, const CompareEntry& second) {
    if (!first.outcome || !second.outcome) {
        return std::nullopt;
    }
    return compare_responses(first.outcome->response, second.outcome->response);
}

} // 命名空间 dnslab::app
