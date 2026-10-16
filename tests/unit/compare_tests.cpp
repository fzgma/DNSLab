#include "app/compare.hpp"

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
    invalid.type = 15;
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
