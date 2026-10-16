#include "dns/wire_codec.hpp"
#include "dns/record_types.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace {

using namespace dnslab::dns;

/// 构造事务 ID 为 0x1234 的 example.com A 查询基准报文。
Packet example_a_query() {
    return {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x07}, std::byte{0x65}, std::byte{0x78}, std::byte{0x61},
        std::byte{0x6D}, std::byte{0x70}, std::byte{0x6C}, std::byte{0x65},
        std::byte{0x03}, std::byte{0x63}, std::byte{0x6F}, std::byte{0x6D},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x01},
    };
}

/// 逐字节比较查询报文与期望编码并记录索引。
void check_bytes(const Packet& packet, std::span<const std::byte> expected) {
    REQUIRE(packet.size() == expected.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        CAPTURE(index);
        CHECK(std::to_integer<unsigned int>(packet[index]) ==
              std::to_integer<unsigned int>(expected[index]));
    }
}

TEST_CASE("查询编码匹配 example.com 的 A 查询基准报文",
          "[query_encoder]") {
    const DnsQuestion question{DnsName{{"example", "com"}}, 1, 1};
    const auto result = encode_query(question, 0x1234);
    REQUIRE(result.has_value());
    check_bytes(*result, example_a_query());
}

TEST_CASE("八种直接查询类型遵守两种递归标志状态",
          "[query_encoder]") {
    for (const auto type : {std::uint16_t{1}, std::uint16_t{28}, std::uint16_t{5},
                            std::uint16_t{15}, std::uint16_t{16}, std::uint16_t{2},
                            std::uint16_t{6}, std::uint16_t{12}}) {
        for (const bool recursion_desired : {false, true}) {
            CAPTURE(type, recursion_desired);
            const DnsQuestion question{DnsName{{"example", "com"}}, type, 1};
            const auto result = encode_query(question, 0x1234, recursion_desired);
            REQUIRE(result.has_value());

            auto expected = example_a_query();
            expected[2] = recursion_desired ? std::byte{0x01} : std::byte{0x00};
            expected[26] = static_cast<std::byte>(type);
            check_bytes(*result, expected);
        }
    }
}

TEST_CASE("查询编码保留调用方提供的事务 ID",
          "[query_encoder]") {
    struct Sample {
        std::uint16_t id;
        std::array<std::byte, 2> bytes;
    };
    constexpr std::array samples{
        Sample{0x0000, {std::byte{0x00}, std::byte{0x00}}},
        Sample{0x8000, {std::byte{0x80}, std::byte{0x00}}},
        Sample{0xFFFF, {std::byte{0xFF}, std::byte{0xFF}}},
    };
    const DnsQuestion question{DnsName{{"example", "com"}}, 1, 1};

    for (const auto& sample : samples) {
        CAPTURE(sample.id);
        const auto result = encode_query(question, sample.id);
        REQUIRE(result.has_value());
        auto expected = example_a_query();
        expected[0] = sample.bytes[0];
        expected[1] = sample.bytes[1];
        check_bytes(*result, expected);
    }
}

TEST_CASE("查询编码接受根名",
          "[query_encoder]") {
    const DnsQuestion question{DnsName{}, 1, 1};
    const Packet expected{
        std::byte{0x12}, std::byte{0x34}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x01},
    };
    const auto result = encode_query(question, 0x1234);
    REQUIRE(result.has_value());
    check_bytes(*result, expected);
}

TEST_CASE("查询编码接受完整的 255 字节未压缩名称",
          "[query_encoder][bounds]") {
    const DnsQuestion question{
        DnsName{{std::string(63, 'a'), std::string(63, 'a'),
                  std::string(63, 'a'), std::string(61, 'a')}}, 1, 1};
    Packet expected{
        std::byte{0x12}, std::byte{0x34}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };
    expected.resize(271, std::byte{0x61});
    expected[12] = std::byte{63};
    expected[76] = std::byte{63};
    expected[140] = std::byte{63};
    expected[204] = std::byte{61};
    expected[266] = std::byte{0};
    expected[267] = std::byte{0};
    expected[268] = std::byte{1};
    expected[269] = std::byte{0};
    expected[270] = std::byte{1};

    const auto result = encode_query(question, 0x1234);
    REQUIRE(result.has_value());
    check_bytes(*result, expected);
}

TEST_CASE("查询编码保留任意标签字节",
          "[query_encoder]") {
    const std::string label{'\0', static_cast<char>(27), '.', '\\',
                            static_cast<char>(0xC0), static_cast<char>(0xFF), 'A'};
    const DnsQuestion question{DnsName{{label}}, 1, 1};
    const Packet expected{
        std::byte{0x12}, std::byte{0x34}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x07}, std::byte{0x00}, std::byte{0x1B}, std::byte{0x2E},
        std::byte{0x5C}, std::byte{0xC0}, std::byte{0xFF}, std::byte{0x41},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x01},
    };
    const auto result = encode_query(question, 0x1234);
    REQUIRE(result.has_value());
    check_bytes(*result, expected);
}

TEST_CASE("查询编码不应用纯数字主机名的输入限制",
          "[query_encoder]") {
    const DnsQuestion question{DnsName{{"123"}}, 1, 1};
    const Packet expected{
        std::byte{0x12}, std::byte{0x34}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x03}, std::byte{0x31}, std::byte{0x32}, std::byte{0x33},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x01},
    };
    const auto result = encode_query(question, 0x1234);
    REQUIRE(result.has_value());
    check_bytes(*result, expected);
}

TEST_CASE("查询名称错误先于类型和类别检查并保留标签索引",
          "[query_encoder][bounds]") {
    struct Sample {
        DnsName name;
        DnsEncodeErrorCode code;
        std::size_t label_index;
    };
    const std::array samples{
        Sample{DnsName{{""}}, DnsEncodeErrorCode::EmptyLabel, 0},
        Sample{DnsName{{"ok", ""}}, DnsEncodeErrorCode::EmptyLabel, 1},
        Sample{DnsName{{"ok", std::string(64, 'a')}},
               DnsEncodeErrorCode::LabelTooLong, 1},
        Sample{DnsName{{std::string(63, 'a'), std::string(63, 'b'),
                        std::string(63, 'c'), std::string(62, 'd')}},
               DnsEncodeErrorCode::NameTooLong, 3},
    };

    for (const auto& sample : samples) {
        CAPTURE(sample.label_index);
        const DnsQuestion question{sample.name, 255, 3};
        const auto result = encode_query(question, 0x1234);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == sample.code);
        CHECK(result.error().label_index == sample.label_index);
    }
}

TEST_CASE("不支持的查询类型先于查询类别检查报错",
          "[query_encoder]") {
    for (const auto type : {std::uint16_t{0}, std::uint16_t{10}, std::uint16_t{41},
                            std::uint16_t{252}, std::uint16_t{255}, std::uint16_t{65535}}) {
        for (const auto qclass : {std::uint16_t{1}, std::uint16_t{3}}) {
            CAPTURE(type, qclass);
            const DnsQuestion question{DnsName{{"example", "com"}}, type, qclass};
            const auto result = encode_query(question, 0x1234);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == DnsEncodeErrorCode::UnsupportedQueryType);
            CHECK(result.error().label_index == 0);
        }
    }
}

TEST_CASE("查询编码仅接受 IN 类别",
          "[query_encoder]") {
    for (const auto type : {std::uint16_t{1}, std::uint16_t{28}, std::uint16_t{5},
                            std::uint16_t{15}, std::uint16_t{16}, std::uint16_t{2},
                            std::uint16_t{6}, std::uint16_t{12}}) {
        for (const auto qclass : {std::uint16_t{0}, std::uint16_t{3},
                                  std::uint16_t{255}, std::uint16_t{65535}}) {
            CAPTURE(type, qclass);
            const DnsQuestion question{DnsName{{"example", "com"}}, type, qclass};
            const auto result = encode_query(question, 0x1234);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == DnsEncodeErrorCode::UnsupportedQueryClass);
            CHECK(result.error().label_index == 0);
        }
    }
}

TEST_CASE("查询类型文本仅接受八种名称并忽略 ASCII 大小写",
          "[query_encoder][query_types]") {
    struct Sample {
        std::string_view text;
        std::string_view canonical;
        std::uint16_t type;
    };
    constexpr std::array samples{
        Sample{"a", "A", 1}, Sample{"AaAa", "AAAA", 28},
        Sample{"cNaMe", "CNAME", 5}, Sample{"mX", "MX", 15},
        Sample{"tXt", "TXT", 16}, Sample{"nS", "NS", 2},
        Sample{"sOa", "SOA", 6}, Sample{"pTr", "PTR", 12},
    };
    for (const auto& sample : samples) {
        CAPTURE(sample.text);
        CHECK(query_type_from_text(sample.text) == sample.type);
        CHECK(query_type_from_text(sample.canonical) == sample.type);
        CHECK(is_supported_query_type(sample.type));
        CHECK(query_type_name(sample.type) == sample.canonical);
    }
    CHECK(query_type_choices == "A|AAAA|CNAME|MX|TXT|NS|SOA|PTR");
}

TEST_CASE("查询类型文本拒绝传送通配编号空白及隐藏字符",
          "[query_encoder][query_types]") {
    const std::array invalid{
        std::string_view{""}, std::string_view{"ANY"}, std::string_view{"AXFR"},
        std::string_view{"IXFR"}, std::string_view{"1"}, std::string_view{"28"},
        std::string_view{"TYPE1"}, std::string_view{"TYPE15"}, std::string_view{"A "},
        std::string_view{" A"}, std::string_view{"TXT\n"}, std::string_view{"MX\0", 3},
        std::string_view{"\xff"},
    };
    for (const auto text : invalid) {
        CAPTURE(text);
        CHECK_FALSE(query_type_from_text(text).has_value());
    }
    for (const auto type : {std::uint16_t{0}, std::uint16_t{10}, std::uint16_t{41},
                            std::uint16_t{252}, std::uint16_t{255}, std::uint16_t{65535}}) {
        CAPTURE(type);
        CHECK_FALSE(is_supported_query_type(type));
        CHECK(query_type_name(type).empty());
    }
}

} // 命名空间
