#include "net/encrypted_transport.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <string_view>
#include <utility>

namespace {

using namespace dnslab::net;
using namespace std::string_view_literals;

/// 断言无效加密端点在内存校验阶段失败且没有后端错误信息。
void check_invalid(const std::expected<EncryptedEndpoint, EncryptedError>& result) {
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == EncryptedErrorCode::InvalidEndpoint);
    CHECK(result.error().backend_code == 0);
    CHECK(result.error().http_status == 0);
}

} // 匿名命名空间

TEST_CASE("DoH 端点规范化服务器地址并保留路径和查询参数", "[encrypted][endpoint]") {
    const std::array pairs{
        std::pair{"https://DNS.Example/dns-query"sv, "https://dns.example:443/dns-query"sv},
        std::pair{"HTTPS://LOCALHOST"sv, "https://localhost:443/"sv},
        std::pair{"https://dns.example./"sv, "https://dns.example:443/"sv},
        std::pair{"https://127.0.0.1:8443/dns-query?x=A%2Fb"sv,
                  "https://127.0.0.1:8443/dns-query?x=A%2Fb"sv},
        std::pair{"https://[2001:0DB8:0:0:0:0:0:1]/dns-query"sv,
                  "https://[2001:db8::1]:443/dns-query"sv},
        std::pair{"https://[::1]:1?fixture=1"sv, "https://[::1]:1/?fixture=1"sv},
        std::pair{"https://xn--bcher-kva.example:65535/Case%20Sensitive"sv,
                  "https://xn--bcher-kva.example:65535/Case%20Sensitive"sv},
    };
    for (const auto& [input, expected] : pairs) {
        CAPTURE(input);
        const auto endpoint = parse_doh_endpoint(input);
        REQUIRE(endpoint.has_value());
        CHECK(endpoint->transport == EncryptedTransport::Doh);
        CHECK(endpoint->address == expected);
    }
}

TEST_CASE("DoT 端点保留地址身份且默认使用 853 端口", "[encrypted][endpoint]") {
    const std::array pairs{
        std::pair{"DNS.Example"sv, "dns.example:853"sv},
        std::pair{"localhost."sv, "localhost:853"sv},
        std::pair{"127.0.0.1"sv, "127.0.0.1:853"sv},
        std::pair{"127.0.0.1:8853"sv, "127.0.0.1:8853"sv},
        std::pair{"::1"sv, "[::1]:853"sv},
        std::pair{"[::1]"sv, "[::1]:853"sv},
        std::pair{"[2001:0DB8::1]:65535"sv, "[2001:db8::1]:65535"sv},
        std::pair{"123.example:1"sv, "123.example:1"sv},
        std::pair{"xn--bcher-kva.example:00853"sv, "xn--bcher-kva.example:853"sv},
    };
    for (const auto& [input, expected] : pairs) {
        CAPTURE(input);
        const auto endpoint = parse_dot_endpoint(input);
        REQUIRE(endpoint.has_value());
        CHECK(endpoint->transport == EncryptedTransport::Dot);
        CHECK(endpoint->address == expected);
    }
}

TEST_CASE("DoH 必须使用不含凭据或片段的 HTTPS 地址", "[encrypted][endpoint]") {
    for (const auto input : {
             "", "http://dns.example/dns-query", "ftp://dns.example/", "dns.example/dns-query",
             "https://", "https:///dns-query", "https://user@dns.example/",
             "https://user:pass@dns.example/", "https://dns.example/#fragment",
             "https://dns.example:0/", "https://dns.example:65536/",
             "https://dns.example:/", "https://dns.example:+443/",
             "https://dns.example:4x3/", "https://::1/dns-query",
             "https://[::1", "https://[127.0.0.1]/", "https://[::1]extra/",
             "https://[fe80::1%25eth0]/", "https://dns%2eexample/",
             "https://dns.example/%", "https://dns.example/%0", "https://dns.example/%gg"}) {
        CAPTURE(input);
        check_invalid(parse_doh_endpoint(input));
    }
}

TEST_CASE("DoT 拒绝 URL 语法和畸形的主机端口组合", "[encrypted][endpoint]") {
    for (const auto input : {
             "", ".", "https://dns.example", "dns.example/path", "dns.example?query",
             "user@dns.example", "dns.example#fragment", "dns.example:",
             "dns.example:0", "dns.example:65536", "dns.example:-1", "dns.example:8x3",
             "[::1", "[::1]extra", "[::1]:", "[127.0.0.1]:853", "fe80::1%eth0",
             "a..example", "-dns.example", "dns-.example", "dns_example"}) {
        CAPTURE(input);
        check_invalid(parse_dot_endpoint(input));
    }
}

TEST_CASE("加密端点拒绝含糊的数字地址写法", "[encrypted][endpoint]") {
    for (const auto host : {"127.1", "2130706433", "1.2.3", "999.1.1.1",
                            "127.000.0.1", "0177.0.0.1", "0x7f000001", "0x7f.1",
                            "0x7f.0.0.1", "0X7F000001"}) {
        CAPTURE(host);
        check_invalid(parse_dot_endpoint(host));
        check_invalid(parse_doh_endpoint(std::string{"https://"} + host + "/dns-query"));
    }
}

TEST_CASE("加密端点错误保留原始非法字节的偏移", "[encrypted][endpoint]") {
    for (const char invalid : {' ', '\t', '\r', '\n', '\0', '\\', '#',
                               static_cast<char>(0x7f), static_cast<char>(0xc2)}) {
        const std::string dot = std::string{"dns"} + invalid + ".example";
        const std::string doh = std::string{"https://dns"} + invalid + ".example/query";
        const auto dot_result = parse_dot_endpoint(dot);
        const auto doh_result = parse_doh_endpoint(doh);
        check_invalid(dot_result);
        check_invalid(doh_result);
        CHECK(dot_result.error().offset == 3);
        CHECK(doh_result.error().offset == 11);
    }
    const auto bad_port = parse_dot_endpoint("dns.example:8x3");
    check_invalid(bad_port);
    CHECK(bad_port.error().offset == 13);
    const auto empty = parse_doh_endpoint("");
    check_invalid(empty);
    CHECK(empty.error().offset == 0);
}

TEST_CASE("加密端点端口解析拒绝任意超长数值", "[encrypted][endpoint]") {
    const std::string huge(2000, '9');
    check_invalid(parse_dot_endpoint(std::string{"dns.example:"} + huge));
    check_invalid(parse_doh_endpoint(std::string{"https://dns.example:"} + huge + "/"));
    const auto padded = parse_dot_endpoint("dns.example:000853");
    REQUIRE(padded.has_value());
    CHECK(padded->address == "dns.example:853");
}
