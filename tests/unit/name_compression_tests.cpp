#include "dns/name_codec.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace {

using namespace dnslab::dns;

/// 验证压缩名称解码失败时的错误类别和定位偏移。
void check_compression_error(std::span<const std::byte> packet, std::size_t start,
                             DnsParseErrorCode code, std::size_t offset) {
    const auto result = decode_name(packet, start);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().offset == offset);
}

/// 构造三个 63 字节标签及指定末标签长度的边界名称报文。
Packet boundary_suffix(std::size_t wire_size, std::byte last_label_length) {
    Packet packet(wire_size, std::byte{0x61});
    packet[0] = std::byte{63};
    packet[64] = std::byte{63};
    packet[128] = std::byte{63};
    packet[192] = last_label_length;
    packet.back() = std::byte{0};
    return packet;
}

TEST_CASE("压缩指针解码报文中较早出现的后缀",
          "[name_codec][compression]") {
    const Packet packet{std::byte{3}, std::byte{0x63}, std::byte{0x6F},
                        std::byte{0x6D}, std::byte{0}, std::byte{0xC0}, std::byte{0}};
    const auto result = decode_name(packet, 5);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{"com"};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 2);
}

TEST_CASE("普通标签可使用压缩指针结尾",
          "[name_codec][compression]") {
    const Packet packet{
        std::byte{3}, std::byte{0x63}, std::byte{0x6F}, std::byte{0x6D}, std::byte{0},
        std::byte{3}, std::byte{0x77}, std::byte{0x77}, std::byte{0x77},
        std::byte{0xC0}, std::byte{0}};
    const auto result = decode_name(packet, 5);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{"www", "com"};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 6);
}

TEST_CASE("压缩指针可沿多个更早的指针继续解析",
          "[name_codec][compression]") {
    const Packet packet{
        std::byte{3}, std::byte{0x63}, std::byte{0x6F}, std::byte{0x6D}, std::byte{0},
        std::byte{0xC0}, std::byte{0}, std::byte{0xC0}, std::byte{5}};
    const auto result = decode_name(packet, 7);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{"com"};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 2);
}

TEST_CASE("压缩指针可以指向根名",
          "[name_codec][compression]") {
    const Packet packet{std::byte{0}, std::byte{0xC0}, std::byte{0}};
    const auto result = decode_name(packet, 1);
    REQUIRE(result.has_value());
    CHECK(result->name.labels.empty());
    CHECK(result->consumed == 2);
}

TEST_CASE("压缩名称在首个指针之后停止累计原路径消费字节",
          "[name_codec][compression]") {
    const Packet packet{std::byte{0}, std::byte{1}, std::byte{0x61},
                        std::byte{0xC0}, std::byte{0}, std::byte{0x80}};
    const auto original = packet;
    const auto result = decode_name(packet, 1);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{"a"};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 4);
    CHECK(packet == original);
}

TEST_CASE("向后指针仍能检测经普通标签形成的循环",
          "[name_codec][compression][bounds]") {
    const Packet packet{std::byte{1}, std::byte{0x61},
                        std::byte{0xC0}, std::byte{0}};
    check_compression_error(packet, 0, DnsParseErrorCode::CompressionLoop, 0);
    check_compression_error(packet, 2, DnsParseErrorCode::CompressionLoop, 2);
}

TEST_CASE("压缩指针必须包含完整的两个字节",
          "[name_codec][compression][bounds]") {
    const Packet at_start{std::byte{0xC0}};
    check_compression_error(at_start, 0,
                            DnsParseErrorCode::CompressionPointerTruncated, 0);

    const Packet at_offset{std::byte{0}, std::byte{0xC0}};
    check_compression_error(at_offset, 1,
                            DnsParseErrorCode::CompressionPointerTruncated, 1);
}

TEST_CASE("压缩指针拒绝报文之外的目标",
          "[name_codec][compression][bounds]") {
    const Packet packet{std::byte{0xC0}, std::byte{0xFF}};
    check_compression_error(packet, 0,
                            DnsParseErrorCode::CompressionPointerOutOfBounds, 0);
}

TEST_CASE("压缩指针拒绝自身引用和向前引用",
          "[name_codec][compression][bounds]") {
    const Packet self{std::byte{0xC0}, std::byte{0}};
    check_compression_error(self, 0,
                            DnsParseErrorCode::CompressionPointerNotBackward, 0);

    const Packet forward{std::byte{0xC0}, std::byte{2}, std::byte{0}};
    check_compression_error(forward, 0,
                            DnsParseErrorCode::CompressionPointerNotBackward, 0);

    const Packet offset_forward{
        std::byte{0}, std::byte{0xC0}, std::byte{3}, std::byte{0}};
    check_compression_error(offset_forward, 1,
                            DnsParseErrorCode::CompressionPointerNotBackward, 1);
}

TEST_CASE("经指针访问的非法标签报告目标位置",
          "[name_codec][compression][bounds]") {
    for (const auto marker : {0x40, 0x80}) {
        CAPTURE(marker);
        const Packet packet{
            static_cast<std::byte>(marker), std::byte{0xC0}, std::byte{0}};
        check_compression_error(packet, 1,
                                DnsParseErrorCode::ReservedLabelEncoding, 0);
    }

    const Packet truncated_label{
        std::byte{5}, std::byte{0x61}, std::byte{0xC0}, std::byte{0}};
    check_compression_error(truncated_label, 2,
                            DnsParseErrorCode::NameOutOfBounds, 0);
}

TEST_CASE("压缩标签保留控制字节和类似指针的数据",
          "[name_codec][compression]") {
    const Packet packet{
        std::byte{7}, std::byte{0}, std::byte{27}, std::byte{46}, std::byte{92},
        std::byte{0xC0}, std::byte{0x40}, std::byte{0xFF}, std::byte{0},
        std::byte{0xC0}, std::byte{0}};
    const std::string expected{
        '\0', static_cast<char>(27), '.', '\\', static_cast<char>(0xC0),
        '@', static_cast<char>(0xFF)};

    const auto result = decode_name(packet, 9);
    REQUIRE(result.has_value());
    REQUIRE(result->name.labels.size() == 1);
    CHECK(result->name.labels.front() == expected);
    CHECK(result->consumed == 2);
}

TEST_CASE("压缩名称前缀允许展开为恰好 255 字节",
          "[name_codec][compression][bounds]") {
    auto packet = boundary_suffix(253, std::byte{59});
    packet.insert(packet.end(), {std::byte{1}, std::byte{0x78},
                                  std::byte{0xC0}, std::byte{0}});

    const auto result = decode_name(packet, 253);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{
        "x", std::string(63, 'a'), std::string(63, 'a'),
        std::string(63, 'a'), std::string(59, 'a')};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 4);
}

TEST_CASE("压缩名称前缀不能展开为超过 255 字节",
          "[name_codec][compression][bounds]") {
    auto packet = boundary_suffix(254, std::byte{60});
    packet.insert(packet.end(), {std::byte{1}, std::byte{0x78},
                                  std::byte{0xC0}, std::byte{0}});
    check_compression_error(packet, 254,
                            DnsParseErrorCode::ExpandedNameTooLong, 192);
}

TEST_CASE("单个指针可以引用完整的 255 字节名称",
          "[name_codec][compression][bounds]") {
    auto packet = boundary_suffix(255, std::byte{61});
    packet.insert(packet.end(), {std::byte{0xC0}, std::byte{0}});

    const auto result = decode_name(packet, 255);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{
        std::string(63, 'a'), std::string(63, 'a'),
        std::string(63, 'a'), std::string(61, 'a')};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 2);
}

TEST_CASE("名称展开长度与压缩路径消费字节数独立",
          "[name_codec][compression][bounds]") {
    Packet packet(257, std::byte{0x61});
    packet[0] = std::byte{0};
    packet[1] = std::byte{63};
    packet[65] = std::byte{63};
    packet[129] = std::byte{63};
    packet[193] = std::byte{61};
    packet[255] = std::byte{0xC0};
    packet[256] = std::byte{0};

    const auto result = decode_name(packet, 1);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{
        std::string(63, 'a'), std::string(63, 'a'),
        std::string(63, 'a'), std::string(61, 'a')};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 256);
}

TEST_CASE("压缩指针使用全部十四位偏移",
          "[name_codec][compression][bounds]") {
    Packet packet(16386, std::byte{0});
    packet[16384] = std::byte{0xFF};
    packet[16385] = std::byte{0xFF};

    const auto result = decode_name(packet, 16384);
    REQUIRE(result.has_value());
    CHECK(result->name.labels.empty());
    CHECK(result->consumed == 2);
}

TEST_CASE("较长的无环向后指针链能够到达根名",
          "[name_codec][compression][bounds]") {
    Packet packet(603, std::byte{0});
    for (std::size_t offset = 1; offset <= 601; offset += 2) {
        const std::size_t target = offset == 1 ? 0 : offset - 2;
        packet[offset] = static_cast<std::byte>(0xC0U | (target >> 8));
        packet[offset + 1] = static_cast<std::byte>(target & 0xFFU);
    }

    const auto result = decode_name(packet, 601);
    REQUIRE(result.has_value());
    CHECK(result->name.labels.empty());
    CHECK(result->consumed == 2);
}

} // 命名空间
