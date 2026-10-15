#include "net/endpoint.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <variant>

namespace {

using namespace dnslab::net;

/// 验证端点解析失败时的错误类别和原输入偏移。
void check_error(std::string_view input, EndpointInputErrorCode code,
                 std::size_t offset) {
    const auto result = parse_endpoint(input);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().offset == offset);
}

TEST_CASE("IPv4 端点保留地址字节并规范化显式端口",
          "[endpoint][ipv4]") {
    for (const auto input : {"192.0.2.1", "192.0.2.1:53", "192.0.2.1:00053"}) {
        CAPTURE(input);
        const auto result = parse_endpoint(input);
        REQUIRE(result.has_value());
        CHECK(result->family() == IpFamily::V4);
        CHECK(result->port == 53);
        REQUIRE(std::holds_alternative<Ipv4Address>(result->address));
        const Ipv4Address expected{std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1}};
        CHECK(std::get<Ipv4Address>(result->address) == expected);
        CHECK(format_endpoint(*result) == "192.0.2.1:53");
    }

    for (const auto input : {"0.0.0.0", "255.255.255.255", "224.0.0.1", "127.0.0.1"}) {
        CAPTURE(input);
        const auto result = parse_endpoint(input);
        REQUIRE(result.has_value());
        CHECK(format_endpoint(*result) == std::string{input} + ":53");
    }
}

TEST_CASE("IPv6 地址转换保留网络字节序且无需初始化套接字",
          "[endpoint][ipv6]") {
    for (const auto input : {"2001:db8::1", "[2001:DB8:0:0:0:0:0:1]:00053"}) {
        CAPTURE(input);
        const auto result = parse_endpoint(input);
        REQUIRE(result.has_value());
        CHECK(result->family() == IpFamily::V6);
        CHECK(result->port == 53);
        REQUIRE(std::holds_alternative<Ipv6Address>(result->address));
        const Ipv6Address expected{
            std::byte{0x20}, std::byte{0x01}, std::byte{0x0d}, std::byte{0xb8},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
        CHECK(std::get<Ipv6Address>(result->address) == expected);
        CHECK(format_endpoint(*result) == "[2001:db8::1]:53");
    }
    const auto bare = parse_endpoint("2001:db8::1:53");
    REQUIRE(bare.has_value());
    CHECK(bare->port == 53);
    CHECK(format_endpoint(*bare) == "[2001:db8::1:53]:53");

    for (const auto input : {"::", "::1", "ff02::1", "fe80::1"}) {
        CAPTURE(input);
        REQUIRE(parse_endpoint(input).has_value());
    }
}

TEST_CASE("IPv6 格式化压缩最长且最靠左的多段连续零",
          "[endpoint][format]") {
    struct Sample {
        std::string_view input;
        std::string_view output;
    };
    const std::array samples{
        Sample{"0:0:0:0:0:0:0:0", "[::]:53"},
        Sample{"0:0:0:0:0:0:0:1", "[::1]:53"},
        Sample{"1:2:3:4:5:6:0:0", "[1:2:3:4:5:6::]:53"},
        Sample{"0:0:1:2:3:4:5:6", "[::1:2:3:4:5:6]:53"},
        Sample{"1:2:3:4:5:6:0:8", "[1:2:3:4:5:6:0:8]:53"},
        Sample{"2001:0DB8:0000:0000:0001:0000:0000:0001",
               "[2001:db8::1:0:0:1]:53"},
        Sample{"1:0:0:2:0:0:0:3", "[1:0:0:2::3]:53"},
        Sample{"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:65535",
               "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"},
    };
    for (const auto& sample : samples) {
        CAPTURE(sample.input);
        const auto parsed = parse_endpoint(sample.input);
        REQUIRE(parsed.has_value());
        CHECK(format_endpoint(*parsed) == sample.output);
        const auto reparsed = parse_endpoint(format_endpoint(*parsed));
        REQUIRE(reparsed.has_value());
        CHECK(*reparsed == *parsed);
    }
}

TEST_CASE("混合 IPv6 尾部遵循严格 IPv4 语法并规范为十六进制",
          "[endpoint][ipv6][format]") {
    struct Sample {
        std::string_view input;
        std::string_view output;
    };
    const std::array samples{
        Sample{"::ffff:192.0.2.1", "[::ffff:c000:201]:53"},
        Sample{"::192.0.2.1", "[::c000:201]:53"},
        Sample{"2001:db8:0:1:2:3:192.0.2.1", "[2001:db8:0:1:2:3:c000:201]:53"},
        Sample{"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
               "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:53"},
    };
    for (const auto& sample : samples) {
        CAPTURE(sample.input);
        const auto result = parse_endpoint(sample.input);
        REQUIRE(result.has_value());
        CHECK(result->family() == IpFamily::V6);
        CHECK(format_endpoint(*result) == sample.output);
    }
    for (const auto input : {"::ffff:192.00.2.1", "::ffff:256.0.0.1",
                             "::ffff:192.0.2", "::ffff:192.0.2.1.2"}) {
        CAPTURE(input);
        check_error(input, EndpointInputErrorCode::InvalidAddress, 0);
    }
}

TEST_CASE("端点解析拒绝主机名 URL 和非标准 IP 格式",
          "[endpoint][invalid]") {
    for (const auto input : {"example.com", "localhost", "https://1.2.3.4", "1.2.3.4/path",
                             "user@1.2.3.4", "1", "1.2.3", "1.2.3.4.5", "1..3.4",
                             "1.2.3.4.", ".1.2.3.4", "256.0.0.1", "01.2.3.4",
                             "1.2.3.004", "0x7f.0.0.1", "+1.2.3.4", "-1.2.3.4",
                             "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "12345::",
                             "1::2::3", ":::"}) {
        CAPTURE(input);
        check_error(input, EndpointInputErrorCode::InvalidAddress, 0);
    }
    check_error("", EndpointInputErrorCode::EmptyInput, 0);
    check_error("[1.2.3.4]:53", EndpointInputErrorCode::InvalidAddress, 1);
    check_error("[]:53", EndpointInputErrorCode::InvalidAddress, 1);
    check_error("[::1", EndpointInputErrorCode::InvalidFormat, 4);
    check_error("[::1]x53", EndpointInputErrorCode::InvalidFormat, 5);
    check_error("::1]", EndpointInputErrorCode::InvalidFormat, 3);
    check_error("[::1]", EndpointInputErrorCode::MissingPort, 5);
    check_error("[::1]:", EndpointInputErrorCode::MissingPort, 6);
}

TEST_CASE("端点校验保留隐藏字符及不支持字符的原始字节偏移",
          "[endpoint][invalid]") {
    struct Sample {
        std::string input;
        std::size_t offset;
    };
    const std::array samples{
        Sample{" 1.2.3.4", 0}, Sample{"1.2.3.4 ", 7},
        Sample{"1.2.3.4\t:53", 7}, Sample{"1.2.3.4\n", 7},
        Sample{"1.2.3.4\r", 7}, Sample{"1.2.3.4\x7f", 7},
        Sample{std::string{"1.2.3.4\0:53", 11}, 7},
        Sample{std::string{"[::1]:53\0", 9}, 8},
        Sample{"1\xEF\xBC\x8E" "2.3.4", 1},
        Sample{"::1\xE2\x80\x8B", 3},
        Sample{"fe80::1%3", 7}, Sample{"[fe80::1%eth0]:53", 8},
    };
    for (const auto& sample : samples) {
        CAPTURE(sample.offset);
        check_error(sample.input, EndpointInputErrorCode::InvalidCharacter, sample.offset);
    }
}

TEST_CASE("端口接受十进制边界值并拒绝溢出及正负号",
          "[endpoint][port]") {
    struct Valid {
        std::string_view input;
        std::uint16_t port;
    };
    for (const auto sample : {Valid{"1.2.3.4:1", 1}, Valid{"1.2.3.4:65535", 65535},
                               Valid{"[::1]:000000001", 1}, Valid{"[::1]:65535", 65535}}) {
        CAPTURE(sample.input);
        const auto parsed = parse_endpoint(sample.input);
        REQUIRE(parsed.has_value());
        CHECK(parsed->port == sample.port);
    }
    check_error("1.2.3.4:", EndpointInputErrorCode::MissingPort, 8);
    check_error("1.2.3.4:+53", EndpointInputErrorCode::InvalidPort, 8);
    check_error("1.2.3.4:-1", EndpointInputErrorCode::InvalidPort, 8);
    check_error("1.2.3.4:5a3", EndpointInputErrorCode::InvalidPort, 9);
    check_error("[::1]:53:54", EndpointInputErrorCode::InvalidPort, 8);
    for (const auto port : {"0", "000", "65536", "99999999999999999999999999999"}) {
        CAPTURE(port);
        check_error(std::string{"1.2.3.4:"} + port,
                    EndpointInputErrorCode::PortOutOfRange, 8);
    }
}

TEST_CASE("端点列表拒绝等价写法并标识首次出现的位置",
          "[endpoint][list]") {
    struct Sample {
        std::array<std::string_view, 3> inputs;
        std::size_t first;
    };
    const std::array samples{
        Sample{{"1.2.3.4", "8.8.8.8:5353", "1.2.3.4:00053"}, 0},
        Sample{{"1.2.3.4", "::1", "[0:0:0:0:0:0:0:1]:53"}, 1},
        Sample{{"::ffff:192.0.2.1", "1.2.3.4", "[::ffff:c000:201]:53"}, 0},
    };
    for (const auto& sample : samples) {
        const auto result = parse_unique_endpoints(sample.inputs);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().error.code == EndpointInputErrorCode::DuplicateEndpoint);
        CHECK(result.error().error.offset == 0);
        CHECK(result.error().input_index == 2);
        REQUIRE(result.error().first_duplicate_index.has_value());
        CHECK(*result.error().first_duplicate_index == sample.first);
    }
}

TEST_CASE("端点列表保留顺序并区分端口和地址族",
          "[endpoint][list]") {
    const std::array<std::string_view, 3> inputs{
        "192.0.2.1", "192.0.2.1:54", "::ffff:192.0.2.1"};
    const auto result = parse_unique_endpoints(inputs);
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 3);
    CHECK(format_endpoint((*result)[0]) == "192.0.2.1:53");
    CHECK(format_endpoint((*result)[1]) == "192.0.2.1:54");
    CHECK(format_endpoint((*result)[2]) == "[::ffff:c000:201]:53");
    CHECK((*result)[0] != (*result)[1]);
    CHECK((*result)[0] != (*result)[2]);
    CHECK((*result)[0].family() == IpFamily::V4);
    CHECK((*result)[2].family() == IpFamily::V6);

    const auto empty = parse_unique_endpoints({});
    REQUIRE(empty.has_value());
    CHECK(empty->empty());
}

TEST_CASE("端点列表优先报告非法输入而非之后的重复项",
          "[endpoint][list]") {
    const std::array<std::string_view, 3> inputs{"1.2.3.4", "[::1]:0", "1.2.3.4"};
    const auto result = parse_unique_endpoints(inputs);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().input_index == 1);
    CHECK(result.error().error.code == EndpointInputErrorCode::PortOutOfRange);
    CHECK(result.error().error.offset == 6);
    CHECK_FALSE(result.error().first_duplicate_index.has_value());
}

} // 命名空间
