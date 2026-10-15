#include "dns/types.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

namespace {

using namespace dnslab::dns;

constexpr DnsHeader compile_time_header{0x1234, 0xffff};
static_assert(compile_time_header.is_response() &&
              compile_time_header.opcode() == 15 &&
              compile_time_header.authoritative_answer() &&
              compile_time_header.truncated() &&
              compile_time_header.recursion_desired() &&
              compile_time_header.recursion_available() &&
              compile_time_header.authenticated_data() &&
              compile_time_header.checking_disabled() &&
              compile_time_header.rcode() == 15);
static_assert(noexcept(compile_time_header.is_response()) &&
              noexcept(compile_time_header.opcode()) &&
              noexcept(compile_time_header.authoritative_answer()) &&
              noexcept(compile_time_header.truncated()) &&
              noexcept(compile_time_header.recursion_desired()) &&
              noexcept(compile_time_header.recursion_available()) &&
              noexcept(compile_time_header.authenticated_data()) &&
              noexcept(compile_time_header.checking_disabled()) &&
              noexcept(compile_time_header.rcode()));

TEST_CASE("DNS 报文头字段默认均为零", "[dns_header]") {
    const DnsHeader header;

    CHECK(header.id == 0);
    CHECK(header.flags == 0);
    CHECK_FALSE(header.is_response());
    CHECK(header.opcode() == 0);
    CHECK_FALSE(header.authoritative_answer());
    CHECK_FALSE(header.truncated());
    CHECK_FALSE(header.recursion_desired());
    CHECK_FALSE(header.recursion_available());
    CHECK_FALSE(header.authenticated_data());
    CHECK_FALSE(header.checking_disabled());
    CHECK(header.rcode() == 0);
}

TEST_CASE("DNS 报文头各标志位只影响对应字段", "[dns_header]") {
    for (unsigned int bit = 0; bit < 16; ++bit) {
        const auto flags = static_cast<std::uint16_t>(1U << bit);
        const DnsHeader header{0xbeef, flags};
        CAPTURE(bit, flags);

        CHECK(header.is_response() == (bit == 15));
        CHECK(header.authoritative_answer() == (bit == 10));
        CHECK(header.truncated() == (bit == 9));
        CHECK(header.recursion_desired() == (bit == 8));
        CHECK(header.recursion_available() == (bit == 7));
        CHECK(header.authenticated_data() == (bit == 5));
        CHECK(header.checking_disabled() == (bit == 4));

        const auto expected_opcode = bit >= 11 && bit <= 14 ? 1U << (bit - 11) : 0U;
        const auto expected_rcode = bit < 4 ? 1U << bit : 0U;
        CHECK(header.opcode() == expected_opcode);
        CHECK(header.rcode() == expected_rcode);
        CHECK(header.id == 0xbeef);
        CHECK(header.flags == flags);
    }
}

TEST_CASE("DNS 报文头访问器支持所有标志同时置位", "[dns_header]") {
    const DnsHeader header{0xabcd, 0xffff};

    CHECK(header.is_response());
    CHECK(header.authoritative_answer());
    CHECK(header.truncated());
    CHECK(header.recursion_desired());
    CHECK(header.recursion_available());
    CHECK(header.authenticated_data());
    CHECK(header.checking_disabled());
    CHECK(header.opcode() == 15);
    CHECK(header.rcode() == 15);
    CHECK(header.id == 0xabcd);
    CHECK(header.flags == 0xffff);
}

TEST_CASE("DNS 操作码和响应码在所有取值下保持独立",
          "[dns_header]") {
    for (unsigned int opcode = 0; opcode < 16; ++opcode) {
        for (unsigned int rcode = 0; rcode < 16; ++rcode) {
            // 操作码和响应码之外的位保持置位，其中包括第 6 位保留位。
            const auto flags = static_cast<std::uint16_t>(
                0x87f0U | (opcode << 11) | rcode);
            const DnsHeader header{0x4567, flags};
            CAPTURE(opcode, rcode);

            CHECK(header.opcode() == opcode);
            CHECK(header.rcode() == rcode);
            CHECK(header.is_response());
            CHECK(header.authoritative_answer());
            CHECK(header.truncated());
            CHECK(header.recursion_desired());
            CHECK(header.recursion_available());
            CHECK(header.authenticated_data());
            CHECK(header.checking_disabled());
            CHECK(header.id == 0x4567);
            CHECK(header.flags == flags);
        }
    }
}

TEST_CASE("未知 DNS 报文头标志位保留在原始 flags 中", "[dns_header]") {
    const DnsHeader known{0x1234, 0x9185};
    const DnsHeader with_reserved_bit{0x1234, 0x91c5};

    CHECK(with_reserved_bit.is_response() == known.is_response());
    CHECK(with_reserved_bit.opcode() == known.opcode());
    CHECK(with_reserved_bit.authoritative_answer() == known.authoritative_answer());
    CHECK(with_reserved_bit.truncated() == known.truncated());
    CHECK(with_reserved_bit.recursion_desired() == known.recursion_desired());
    CHECK(with_reserved_bit.recursion_available() == known.recursion_available());
    CHECK(with_reserved_bit.authenticated_data() == known.authenticated_data());
    CHECK(with_reserved_bit.checking_disabled() == known.checking_disabled());
    CHECK(with_reserved_bit.rcode() == known.rcode());
    CHECK(with_reserved_bit.id == known.id);
    CHECK(known.flags == 0x9185);
    CHECK(with_reserved_bit.flags == 0x91c5);
}

} // 命名空间
