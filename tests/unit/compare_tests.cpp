#include "app/compare.hpp"
#include "dns/byte_utils.hpp"
#include "dns/wire_codec.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <utility>

namespace {

using namespace dnslab;
using namespace std::chrono_literals;

/// 构造供纯内存预检使用的回环端点，不创建套接字。
net::Endpoint endpoint(std::uint16_t port = 10053) {
    return {net::Ipv4Address{std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1}}, port};
}

/// 构造标准 IN A 问题，用于比较接口的输入与结果。
dns::DnsQuestion question() {
    return {dns::DnsName{{"example", "com"}}, 1, 1};
}

/// 构造可按地址末字节和 TTL 区分的 A 记录。
dns::ResourceRecord address_record(unsigned char last = 1, std::uint32_t ttl = 60) {
    return {question().name, 1, 1, ttl,
        dns::AData{{std::byte{192}, std::byte{0}, std::byte{2}, static_cast<std::byte>(last)}}};
}

/// 构造包含两条不同地址回答的有效响应模型。
dns::DnsMessage response() {
    dns::DnsMessage result;
    result.header = {123, 0x8180};
    result.questions.push_back(question());
    result.answers = {address_record(1), address_record(2)};
    return result;
}

/// 将内存响应包装为成功条目，避免响应比较测试依赖网络。
app::CompareEntry success(dns::DnsMessage message) {
    return {endpoint(), app::QueryResult{
        endpoint(), question(), message.header.id, app::QueryTransport::Udp,
        std::move(message), 12ms, 0, {}}};
}

/// 构造带一个回答的完整响应，让比较用例覆盖解析前不同的名称压缩布局。
dns::Packet packet_with_answer(std::uint16_t type, const dns::Packet& rdata) {
    auto request = question();
    request.type = type;
    auto encoded = dns::encode_query(request, 123);
    REQUIRE(encoded.has_value());
    auto packet = std::move(*encoded);
    packet[2] = std::byte{0x81};
    packet[3] = std::byte{0x80};
    packet[7] = std::byte{1};
    dns::append_u16_be(packet, 0xc00c);
    dns::append_u16_be(packet, type);
    dns::append_u16_be(packet, 1);
    dns::append_u32_be(packet, 60);
    dns::append_u16_be(packet, static_cast<std::uint16_t>(rdata.size()));
    packet.insert(packet.end(), rdata.begin(), rdata.end());
    return packet;
}

TEST_CASE("响应比较忽略事务 ID、记录顺序和名称 ASCII 大小写", "[compare][difference]") {
    auto first = response();
    first.answers.push_back({dns::DnsName{{"Alias", "example"}}, 5, 1, 40,
                            dns::NameData{dns::DnsName{{"Target", "example"}}}});
    auto second = first;
    second.header.id = 65535;
    second.questions.front().name.labels = {"EXAMPLE", "COM"};
    second.answers[0].owner.labels = {"EXAMPLE", "COM"};
    second.answers.back().owner.labels = {"ALIAS", "EXAMPLE"};
    std::get<dns::NameData>(second.answers.back().rdata).name.labels = {"TARGET", "EXAMPLE"};
    std::ranges::reverse(second.answers);
    CHECK_FALSE(app::compare_responses(first, second).any());
    CHECK_FALSE(app::compare_responses(second, first).any());
}

TEST_CASE("响应比较将 RCODE 与其他原始标志位分别报告", "[compare][difference]") {
    const auto first = response();
    auto second = first;
    second.header.flags |= 3;
    auto differences = app::compare_responses(first, second);
    CHECK(differences.rcode);
    CHECK_FALSE(differences.flags);
    CHECK_FALSE(differences.answers);
    CHECK_FALSE(differences.ttl);
    second.header.flags = static_cast<std::uint16_t>(first.header.flags ^ 0x0040U);
    differences = app::compare_responses(first, second);
    CHECK_FALSE(differences.rcode);
    CHECK(differences.flags);
    CHECK_FALSE(differences.answers);
}

TEST_CASE("响应比较分别报告回答、权威和附加区差异", "[compare][difference]") {
    const auto first = response();
    auto second = first;
    second.answers[0] = address_record(9);
    auto differences = app::compare_responses(first, second);
    CHECK(differences.answers);
    CHECK_FALSE(differences.authority);
    CHECK_FALSE(differences.additional);
    CHECK_FALSE(differences.ttl);
    second = first;
    second.authority.push_back(address_record());
    differences = app::compare_responses(first, second);
    CHECK_FALSE(differences.answers);
    CHECK(differences.authority);
    CHECK_FALSE(differences.additional);
    second = first;
    second.additional.push_back(address_record());
    differences = app::compare_responses(first, second);
    CHECK_FALSE(differences.answers);
    CHECK_FALSE(differences.authority);
    CHECK(differences.additional);
}

TEST_CASE("响应比较不会把不同区段中的相同记录相互抵消", "[compare][difference]") {
    auto first = response();
    first.authority.push_back(address_record(3));
    auto second = first;
    second.additional = std::move(second.authority);
    second.authority.clear();
    const auto differences = app::compare_responses(first, second);
    CHECK_FALSE(differences.answers);
    CHECK(differences.authority);
    CHECK(differences.additional);
    CHECK_FALSE(differences.ttl);
}

TEST_CASE("响应比较独立报告可匹配记录的 TTL 差异", "[compare][ttl]") {
    auto first = response();
    first.authority = {address_record(3)};
    first.additional = {address_record(4)};
    for (const auto section : {0, 1, 2}) {
        CAPTURE(section);
        auto second = first;
        const std::array sections{&second.answers, &second.authority, &second.additional};
        sections[static_cast<std::size_t>(section)]->front().ttl = 0xffffffffU;
        const auto differences = app::compare_responses(first, second);
        CHECK(differences.ttl);
        CHECK_FALSE(differences.answers);
        CHECK_FALSE(differences.authority);
        CHECK_FALSE(differences.additional);
        CHECK_FALSE(differences.rcode);
        CHECK_FALSE(differences.flags);
    }
}

TEST_CASE("响应比较保留重复记录数量且不把纯增删误报为 TTL 变化", "[compare][ttl]") {
    auto first = response();
    first.answers = {address_record(1, 60), address_record(1, 120)};
    auto second = first;
    std::ranges::reverse(second.answers);
    CHECK_FALSE(app::compare_responses(first, second).any());
    second.answers = {address_record(1, 60)};
    auto differences = app::compare_responses(first, second);
    CHECK(differences.answers);
    CHECK_FALSE(differences.ttl);
    CHECK_FALSE(app::compare_responses(second, first).ttl);
    second.answers.push_back(address_record(1, 60));
    differences = app::compare_responses(first, second);
    CHECK_FALSE(differences.answers);
    CHECK(differences.ttl);
    second.answers.push_back(address_record(1, 180));
    differences = app::compare_responses(first, second);
    CHECK(differences.answers);
    CHECK(differences.ttl);
}

TEST_CASE("内容变化与相同记录的 TTL 变化可以同时报告", "[compare][ttl]") {
    const auto first = response();
    auto second = first;
    second.answers[0].ttl = 300;
    second.answers[1] = address_record(9, 900);
    const auto differences = app::compare_responses(first, second);
    CHECK(differences.answers);
    CHECK(differences.ttl);
    second.answers[0].ttl = first.answers[0].ttl;
    CHECK_FALSE(app::compare_responses(first, second).ttl);
}

TEST_CASE("响应比较保留未知类型、类别与 RDATA 的每个字节", "[compare][difference]") {
    auto first = response();
    first.answers = {{question().name, 65000, 65535, 60,
        dns::OpaqueData{{std::byte{0}, std::byte{'A'}, std::byte{255}}}}};
    auto second = first;
    std::get<dns::OpaqueData>(second.answers[0].rdata).bytes[1] = std::byte{'a'};
    CHECK(app::compare_responses(first, second).answers);
    second = first;
    second.answers[0].rr_class = 1;
    CHECK(app::compare_responses(first, second).answers);
    second = first;
    second.answers[0].type = 64999;
    CHECK(app::compare_responses(first, second).answers);
    second = first;
    std::get<dns::OpaqueData>(second.answers[0].rdata).bytes.push_back(std::byte{0});
    CHECK(app::compare_responses(first, second).answers);
}

TEST_CASE("响应比较保留名称标签边界、非 ASCII 及 NUL 后的字节", "[compare][difference]") {
    auto first = response();
    first.answers[0].owner.labels = {"ab", "c"};
    auto second = first;
    second.answers[0].owner.labels = {"a", "bc"};
    CHECK(app::compare_responses(first, second).answers);
    first.answers[0].owner.labels = {std::string{"A\0b", 3}};
    second = first;
    second.answers[0].owner.labels = {std::string{"a\0c", 3}};
    CHECK(app::compare_responses(first, second).answers);
    first.answers[0].owner.labels = {std::string{static_cast<char>(0xc0)}};
    second = first;
    second.answers[0].owner.labels = {std::string{static_cast<char>(0xe0)}};
    CHECK(app::compare_responses(first, second).answers);
}

TEST_CASE("响应比较完整比较 AAAA 地址并区分 CNAME 目标", "[compare][difference]") {
    auto first = response();
    first.answers = {{question().name, 28, 1, 60, dns::AaaaData{}}};
    auto second = first;
    std::get<dns::AaaaData>(second.answers[0].rdata).address.back() = std::byte{1};
    CHECK(app::compare_responses(first, second).answers);
    first.answers = {{question().name, 5, 1, 60,
        dns::NameData{dns::DnsName{{"ab", "c"}}}}};
    second = first;
    std::get<dns::NameData>(second.answers[0].rdata).name.labels = {"a", "bc"};
    CHECK(app::compare_responses(first, second).answers);
}

TEST_CASE("响应比较忽略五种名称记录的压缩布局及 ASCII 大小写", "[compare][difference]") {
    const dns::Packet compressed_name{std::byte{0xc0}, std::byte{12}};
    const dns::Packet expanded_name{
        std::byte{7}, std::byte{'E'}, std::byte{'X'}, std::byte{'A'}, std::byte{'M'},
        std::byte{'P'}, std::byte{'L'}, std::byte{'E'}, std::byte{3}, std::byte{'C'},
        std::byte{'O'}, std::byte{'M'}, std::byte{0}};
    for (const auto type : std::array<std::uint16_t, 5>{2, 5, 6, 12, 15}) {
        CAPTURE(type);
        dns::Packet compressed;
        dns::Packet expanded;
        if (type == 15) {
            dns::append_u16_be(compressed, 65535);
            dns::append_u16_be(expanded, 65535);
        }
        compressed.insert(compressed.end(), compressed_name.begin(), compressed_name.end());
        expanded.insert(expanded.end(), expanded_name.begin(), expanded_name.end());
        if (type == 6) {
            compressed.insert(compressed.end(), compressed_name.begin(), compressed_name.end());
            expanded.insert(expanded.end(), expanded_name.begin(), expanded_name.end());
            for (const auto value : {0xffffffffU, 0x80000000U, 600U, 86400U, 0U}) {
                dns::append_u32_be(compressed, value);
                dns::append_u32_be(expanded, value);
            }
        }
        const auto first = dns::parse_message(packet_with_answer(type, compressed));
        const auto second = dns::parse_message(packet_with_answer(type, expanded));
        REQUIRE(first.has_value());
        REQUIRE(second.has_value());
        CHECK_FALSE(app::compare_responses(*first, *second).any());
        CHECK_FALSE(app::compare_responses(*second, *first).any());
    }
}

TEST_CASE("响应比较保留 NS 和 PTR 目标的标签边界", "[compare][difference]") {
    for (const auto type : std::array<std::uint16_t, 2>{2, 12}) {
        CAPTURE(type);
        auto first = response();
        first.answers = {{question().name, type, 1, 60,
            dns::NameData{dns::DnsName{{"ab", "c"}}}}};
        auto second = first;
        std::get<dns::NameData>(second.answers.front().rdata).name.labels = {"a", "bc"};
        const auto differences = app::compare_responses(first, second);
        CHECK(differences.answers);
        CHECK_FALSE(differences.ttl);
    }
}

TEST_CASE("响应比较独立保留 MX 优先级和交换机名称", "[compare][difference]") {
    auto first = response();
    first.answers = {{question().name, 15, 1, 60,
        dns::MxData{65535, dns::DnsName{{"Mail", "Example"}}}}};
    auto second = first;
    std::get<dns::MxData>(second.answers.front().rdata).exchange.labels = {"MAIL", "EXAMPLE"};
    CHECK_FALSE(app::compare_responses(first, second).any());
    std::get<dns::MxData>(second.answers.front().rdata).preference = 0;
    auto differences = app::compare_responses(first, second);
    CHECK(differences.answers);
    CHECK_FALSE(differences.ttl);
    second = first;
    std::get<dns::MxData>(second.answers.front().rdata).exchange.labels = {"Other", "Example"};
    differences = app::compare_responses(first, second);
    CHECK(differences.answers);
    CHECK_FALSE(differences.ttl);
    first.answers.front().rdata = dns::MxData{10, dns::DnsName{{"ab", "c"}}};
    second = first;
    std::get<dns::MxData>(second.answers.front().rdata).exchange.labels = {"a", "bc"};
    CHECK(app::compare_responses(first, second).answers);
}

TEST_CASE("响应比较逐项保留 SOA 两个名称和五个无符号数值", "[compare][difference]") {
    auto first = response();
    first.answers = {{question().name, 6, 1, 60,
        dns::SoaData{dns::DnsName{{"Ns", "Example"}}, dns::DnsName{{"Admin", "Example"}},
                     0xffffffffU, 0x80000000U, 600, 86400, 0}}};
    auto second = first;
    auto& case_variant = std::get<dns::SoaData>(second.answers.front().rdata);
    case_variant.mname.labels = {"NS", "EXAMPLE"};
    case_variant.rname.labels = {"ADMIN", "EXAMPLE"};
    CHECK_FALSE(app::compare_responses(first, second).any());
    for (const auto field : {&dns::SoaData::mname, &dns::SoaData::rname}) {
        second = first;
        (std::get<dns::SoaData>(second.answers.front().rdata).*field).labels = {"Other", "Example"};
        const auto differences = app::compare_responses(first, second);
        CHECK(differences.answers);
        CHECK_FALSE(differences.ttl);
    }
    for (const auto field : {&dns::SoaData::serial, &dns::SoaData::refresh, &dns::SoaData::retry,
                             &dns::SoaData::expire, &dns::SoaData::minimum}) {
        second = first;
        (std::get<dns::SoaData>(second.answers.front().rdata).*field) ^= 1U;
        const auto differences = app::compare_responses(first, second);
        CHECK(differences.answers);
        CHECK_FALSE(differences.ttl);
    }
}

TEST_CASE("响应比较保留 TXT 大小写、分段、空段及全部字节", "[compare][difference]") {
    auto first = response();
    first.answers = {{question().name, 16, 1, 60,
        dns::TxtData{{{std::byte{'A'}, std::byte{'b'}}, {}, {std::byte{'c'}},
                      {std::byte{0}, std::byte{255}}}}}};
    const auto original = std::get<dns::TxtData>(first.answers.front().rdata).strings;
    for (const auto mutation : {0, 1, 2, 3, 4, 5}) {
        CAPTURE(mutation);
        auto second = first;
        auto& strings = std::get<dns::TxtData>(second.answers.front().rdata).strings;
        switch (mutation) {
        case 0: strings[0][0] = std::byte{'a'}; break;
        case 1:
            strings = {{std::byte{'A'}}, {}, {std::byte{'b'}, std::byte{'c'}}, original.back()};
            break;
        case 2: strings.erase(strings.begin() + 1); break;
        case 3: std::swap(strings[0], strings[2]); break;
        case 4: strings.back().back() = std::byte{254}; break;
        case 5: strings.back().push_back(std::byte{0}); break;
        }
        const auto differences = app::compare_responses(first, second);
        CHECK(differences.answers);
        CHECK_FALSE(differences.ttl);
        CHECK(app::compare_responses(second, first).answers);
    }
}

TEST_CASE("新增记录类型沿用重复数量和独立 TTL 比较规则", "[compare][ttl]") {
    const std::array records{
        dns::ResourceRecord{question().name, 15, 1, 60,
            dns::MxData{10, dns::DnsName{{"mail", "example"}}}},
        dns::ResourceRecord{question().name, 16, 1, 60,
            dns::TxtData{{{}, {std::byte{'A'}}}}},
        dns::ResourceRecord{question().name, 6, 1, 60,
            dns::SoaData{dns::DnsName{{"ns", "example"}}, dns::DnsName{{"admin", "example"}},
                         1, 3600, 600, 86400, 60}}};
    for (const auto& record : records) {
        CAPTURE(record.type);
        auto first = response();
        first.answers = {record, record};
        first.answers.back().ttl = 120;
        auto second = first;
        std::ranges::reverse(second.answers);
        CHECK_FALSE(app::compare_responses(first, second).any());
        second.answers.pop_back();
        auto differences = app::compare_responses(first, second);
        CHECK(differences.answers);
        CHECK_FALSE(differences.ttl);
        second = first;
        second.answers.back().ttl = 60;
        differences = app::compare_responses(first, second);
        CHECK_FALSE(differences.answers);
        CHECK(differences.ttl);
    }
}

TEST_CASE("失败条目不可比较而有效空答案仍可比较", "[compare][difference]") {
    auto empty = response();
    empty.answers.clear();
    const auto first = success(empty);
    auto second = success(empty);
    second.outcome->elapsed = 900ms;
    second.outcome->transport = app::QueryTransport::Tcp;
    const auto equal = app::compare_responses(first, second);
    REQUIRE(equal.has_value());
    CHECK_FALSE(equal->any());
    const app::CompareEntry failure{endpoint(10054),
        std::unexpected(app::QueryError{app::QueryErrorCode::Timeout})};
    CHECK_FALSE(app::compare_responses(first, failure).has_value());
    CHECK_FALSE(app::compare_responses(failure, first).has_value());
    CHECK_FALSE(app::compare_responses(failure, failure).has_value());
}

TEST_CASE("比较预检拒绝不足两个目标及重复端点", "[compare][validation]") {
    const auto missing = app::compare_servers(question(), {});
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().code == app::CompareErrorCode::TooFewServers);
    const std::array one{endpoint()};
    const auto single = app::compare_servers(question(), one);
    REQUIRE_FALSE(single.has_value());
    CHECK(single.error().code == app::CompareErrorCode::TooFewServers);
    const std::array servers{endpoint(), endpoint(10054), endpoint(10055), endpoint(10054)};
    const auto duplicate = app::compare_servers(question(), servers);
    REQUIRE_FALSE(duplicate.has_value());
    CHECK(duplicate.error().code == app::CompareErrorCode::DuplicateEndpoint);
    CHECK(duplicate.error().input_index == 3);
    CHECK(duplicate.error().first_duplicate_index == 1);
}

TEST_CASE("比较预检检查后续端点、模式和预算", "[compare][validation]") {
    const std::array invalid_server{endpoint(), endpoint(0)};
    const auto invalid = app::compare_servers(question(), invalid_server);
    REQUIRE_FALSE(invalid.has_value());
    CHECK(invalid.error().code == app::CompareErrorCode::InvalidEndpoint);
    CHECK(invalid.error().input_index == 1);
    const std::array servers{endpoint(), endpoint(10054)};
    const auto mode = app::compare_servers(question(), servers, static_cast<app::TransportMode>(99));
    REQUIRE_FALSE(mode.has_value());
    CHECK(mode.error().code == app::CompareErrorCode::InvalidMode);
    for (const auto budget : {0ms, 99ms, 30001ms}) {
        CAPTURE(budget.count());
        const auto result = app::compare_servers(question(), servers, app::TransportMode::Auto, budget);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == app::CompareErrorCode::InvalidTimeout);
    }
}

TEST_CASE("比较预检独立校验问题并保留编码错误详情", "[compare][validation]") {
    const std::array servers{endpoint(), endpoint(10054)};
    auto invalid = question();
    invalid.name.labels.push_back("");
    auto result = app::compare_servers(invalid, servers);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().encode_error.has_value());
    CHECK(result.error().code == app::CompareErrorCode::Encode);
    CHECK(result.error().encode_error->code == dns::DnsEncodeErrorCode::EmptyLabel);
    CHECK(result.error().encode_error->label_index == 2);
    invalid = question();
    invalid.type = 255;
    result = app::compare_servers(invalid, servers);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().encode_error.has_value());
    CHECK(result.error().encode_error->code == dns::DnsEncodeErrorCode::UnsupportedQueryType);
    invalid = question();
    invalid.qclass = 3;
    result = app::compare_servers(invalid, servers);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().encode_error.has_value());
    CHECK(result.error().encode_error->code == dns::DnsEncodeErrorCode::UnsupportedQueryClass);
}

} // 匿名命名空间
