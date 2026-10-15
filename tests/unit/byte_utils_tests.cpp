#include "dns/byte_utils.hpp"
#include "dns/errors.hpp"
#include "dns/types.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>

namespace {

using namespace dnslab::dns;

template <typename T>
void require_out_of_bounds(const std::expected<T, DnsParseError>& result,
                           std::size_t offset) {
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == DnsParseErrorCode::FieldOutOfBounds);
    CHECK(result.error().offset == offset);
}

void check_bytes(const Packet& packet, std::span<const std::byte> expected) {
    REQUIRE(packet.size() == expected.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        CAPTURE(index);
        CHECK(std::to_integer<unsigned int>(packet[index]) ==
              std::to_integer<unsigned int>(expected[index]));
    }
}

TEST_CASE("read_u16_be reads network byte order", "[byte_utils][read]") {
    struct Sample {
        std::array<std::byte, 2> bytes;
        std::uint16_t value;
    };
    constexpr std::array samples{
        Sample{{std::byte{0x12}, std::byte{0x34}}, 0x1234},
        Sample{{std::byte{0x00}, std::byte{0x00}}, 0x0000},
        Sample{{std::byte{0x80}, std::byte{0x00}}, 0x8000},
        Sample{{std::byte{0xFF}, std::byte{0xFF}}, 0xFFFF},
    };

    for (const auto& sample : samples) {
        CAPTURE(sample.value);
        const auto result = read_u16_be(sample.bytes, 0);
        REQUIRE(result.has_value());
        CHECK(*result == sample.value);
    }
}

TEST_CASE("read_u32_be reads network byte order", "[byte_utils][read]") {
    struct Sample {
        std::array<std::byte, 4> bytes;
        std::uint32_t value;
    };
    constexpr std::array samples{
        Sample{{std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}},
               0x12345678U},
        Sample{{std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}},
               0x00000000U},
        Sample{{std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}},
               0x80000000U},
        Sample{{std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}},
               0xFFFFFFFFU},
    };

    for (const auto& sample : samples) {
        CAPTURE(sample.value);
        const auto result = read_u32_be(sample.bytes, 0);
        REQUIRE(result.has_value());
        CHECK(*result == sample.value);
    }
}

TEST_CASE("integer reads honor a nonzero offset and allow the exact end",
          "[byte_utils][read]") {
    const Packet packet{std::byte{0xAA}, std::byte{0x12}, std::byte{0x34},
                        std::byte{0x56}, std::byte{0x78}};

    const auto first_word = read_u16_be(packet, 1);
    REQUIRE(first_word.has_value());
    CHECK(*first_word == 0x1234);

    const auto last_word = read_u16_be(packet, 3);
    REQUIRE(last_word.has_value());
    CHECK(*last_word == 0x5678);

    const auto whole_value = read_u32_be(packet, 1);
    REQUIRE(whole_value.has_value());
    CHECK(*whole_value == 0x12345678U);
}

TEST_CASE("read_u16_be rejects every truncated field", "[byte_utils][bounds]") {
    const std::array packet{std::byte{0xAA}, std::byte{0x12}, std::byte{0x34}};
    const std::span<const std::byte> bytes{packet};

    for (std::size_t remaining = 0; remaining < 2; ++remaining) {
        CAPTURE(remaining);
        require_out_of_bounds(read_u16_be(bytes.first(remaining), 0), 0);
        require_out_of_bounds(read_u16_be(bytes.first(1 + remaining), 1), 1);
    }
}

TEST_CASE("read_u32_be rejects every truncated field", "[byte_utils][bounds]") {
    const std::array packet{std::byte{0xAA}, std::byte{0x12}, std::byte{0x34},
                            std::byte{0x56}, std::byte{0x78}};
    const std::span<const std::byte> bytes{packet};

    for (std::size_t remaining = 0; remaining < 4; ++remaining) {
        CAPTURE(remaining);
        require_out_of_bounds(read_u32_be(bytes.first(remaining), 0), 0);
        require_out_of_bounds(read_u32_be(bytes.first(1 + remaining), 1), 1);
    }
}

TEST_CASE("integer reads reject out-of-range offsets without overflow",
          "[byte_utils][bounds]") {
    const Packet packet{std::byte{0x12}, std::byte{0x34}, std::byte{0x56},
                        std::byte{0x78}};
    constexpr auto max_offset = std::numeric_limits<std::size_t>::max();
    const std::array offsets{packet.size(), packet.size() + 1, max_offset - 1,
                             max_offset};

    for (const auto offset : offsets) {
        CAPTURE(offset);
        require_out_of_bounds(read_u16_be(packet, offset), offset);
        require_out_of_bounds(read_u32_be(packet, offset), offset);
        require_out_of_bounds(read_u16_be({}, offset), offset);
        require_out_of_bounds(read_u32_be({}, offset), offset);
    }
}

TEST_CASE("append_u16_be writes network byte order", "[byte_utils][append]") {
    Packet packet;
    append_u16_be(packet, 0x1234);
    const std::array expected{std::byte{0x12}, std::byte{0x34}};
    check_bytes(packet, expected);
}

TEST_CASE("append_u32_be writes network byte order", "[byte_utils][append]") {
    Packet packet;
    append_u32_be(packet, 0x12345678U);
    const std::array expected{std::byte{0x12}, std::byte{0x34}, std::byte{0x56},
                              std::byte{0x78}};
    check_bytes(packet, expected);
}

TEST_CASE("append_u16_be preserves the prefix and all value bits",
          "[byte_utils][append]") {
    Packet packet{std::byte{0xAA}, std::byte{0x55}, std::byte{0xCC}};
    append_u16_be(packet, 0x0000);
    append_u16_be(packet, 0x8000);
    append_u16_be(packet, 0xFFFF);

    const std::array expected{
        std::byte{0xAA}, std::byte{0x55}, std::byte{0xCC},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x80}, std::byte{0x00},
        std::byte{0xFF}, std::byte{0xFF},
    };
    check_bytes(packet, expected);
}

TEST_CASE("append_u32_be preserves the prefix and all value bits",
          "[byte_utils][append]") {
    Packet packet{std::byte{0xAA}, std::byte{0x55}, std::byte{0xCC}};
    append_u32_be(packet, 0x00000000U);
    append_u32_be(packet, 0x80000000U);
    append_u32_be(packet, 0xFFFFFFFFU);

    const std::array expected{
        std::byte{0xAA}, std::byte{0x55}, std::byte{0xCC},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
    };
    check_bytes(packet, expected);
}

} // namespace
