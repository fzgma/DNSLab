#include "dns/name_codec.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace {

using namespace dnslab::dns;

void check_compression_error(std::span<const std::byte> packet, std::size_t start,
                             DnsParseErrorCode code, std::size_t offset) {
    const auto result = decode_name(packet, start);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().offset == offset);
}

// Three 63-byte labels followed by one label of the requested length.
Packet boundary_suffix(std::size_t wire_size, std::byte last_label_length) {
    Packet packet(wire_size, std::byte{0x61});
    packet[0] = std::byte{63};
    packet[64] = std::byte{63};
    packet[128] = std::byte{63};
    packet[192] = last_label_length;
    packet.back() = std::byte{0};
    return packet;
}

TEST_CASE("A compression pointer decodes an earlier suffix",
          "[name_codec][compression]") {
    const Packet packet{std::byte{3}, std::byte{0x63}, std::byte{0x6F},
                        std::byte{0x6D}, std::byte{0}, std::byte{0xC0}, std::byte{0}};
    const auto result = decode_name(packet, 5);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{"com"};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 2);
}

TEST_CASE("Ordinary labels can end with a compression pointer",
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

TEST_CASE("Compression pointers can follow multiple earlier pointers",
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

TEST_CASE("A compression pointer can target the root name",
          "[name_codec][compression]") {
    const Packet packet{std::byte{0}, std::byte{0xC0}, std::byte{0}};
    const auto result = decode_name(packet, 1);
    REQUIRE(result.has_value());
    CHECK(result->name.labels.empty());
    CHECK(result->consumed == 2);
}

TEST_CASE("A compressed name stops consuming bytes after its first pointer",
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

TEST_CASE("Backward pointers still detect cycles through ordinary labels",
          "[name_codec][compression][bounds]") {
    const Packet packet{std::byte{1}, std::byte{0x61},
                        std::byte{0xC0}, std::byte{0}};
    check_compression_error(packet, 0, DnsParseErrorCode::CompressionLoop, 0);
    check_compression_error(packet, 2, DnsParseErrorCode::CompressionLoop, 2);
}

TEST_CASE("Compression pointers require both bytes",
          "[name_codec][compression][bounds]") {
    const Packet at_start{std::byte{0xC0}};
    check_compression_error(at_start, 0,
                            DnsParseErrorCode::CompressionPointerTruncated, 0);

    const Packet at_offset{std::byte{0}, std::byte{0xC0}};
    check_compression_error(at_offset, 1,
                            DnsParseErrorCode::CompressionPointerTruncated, 1);
}

TEST_CASE("Compression pointers reject targets outside the packet",
          "[name_codec][compression][bounds]") {
    const Packet packet{std::byte{0xC0}, std::byte{0xFF}};
    check_compression_error(packet, 0,
                            DnsParseErrorCode::CompressionPointerOutOfBounds, 0);
}

TEST_CASE("Compression pointers reject self and forward references",
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

TEST_CASE("Invalid labels reached through pointers report their target offset",
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

TEST_CASE("Compressed labels preserve control bytes and pointer-like data",
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

TEST_CASE("A compressed prefix can expand to exactly 255 wire bytes",
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

TEST_CASE("A compressed prefix cannot expand beyond 255 wire bytes",
          "[name_codec][compression][bounds]") {
    auto packet = boundary_suffix(254, std::byte{60});
    packet.insert(packet.end(), {std::byte{1}, std::byte{0x78},
                                  std::byte{0xC0}, std::byte{0}});
    check_compression_error(packet, 254,
                            DnsParseErrorCode::ExpandedNameTooLong, 192);
}

TEST_CASE("A pointer alone can reference a full 255-byte name",
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

TEST_CASE("Expanded length is independent of compressed bytes consumed",
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

TEST_CASE("Compression pointers use all fourteen offset bits",
          "[name_codec][compression][bounds]") {
    Packet packet(16386, std::byte{0});
    packet[16384] = std::byte{0xFF};
    packet[16385] = std::byte{0xFF};

    const auto result = decode_name(packet, 16384);
    REQUIRE(result.has_value());
    CHECK(result->name.labels.empty());
    CHECK(result->consumed == 2);
}

TEST_CASE("A long acyclic backward pointer chain reaches the root",
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

} // namespace
