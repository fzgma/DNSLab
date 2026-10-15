#include "dns/wire_codec.hpp"

#include "dns/byte_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace {

using namespace dnslab::dns;

constexpr std::array root_name{std::byte{0}};

/// 构造包含一个 example.com A 问题与应答的固定基准响应。
Packet golden_response() {
    // 事务 ID 为 0x1234，标准响应中包含一个 example.com A 问题和应答。
    return {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x81}, std::byte{0x80},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x07}, std::byte{0x65}, std::byte{0x78}, std::byte{0x61},
        std::byte{0x6d}, std::byte{0x70}, std::byte{0x6c}, std::byte{0x65},
        std::byte{0x03}, std::byte{0x63}, std::byte{0x6f}, std::byte{0x6d},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x01}, std::byte{0xc0}, std::byte{0x0c}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x2c}, std::byte{0x00},
        std::byte{0x04}, std::byte{0x5d}, std::byte{0xb8}, std::byte{0xd8},
        std::byte{0x22},
    };
}

/// 按指定计数、标志和事务 ID 构造 DNS 报文头。
Packet header(std::array<std::uint16_t, 4> counts,
              std::uint16_t flags = 0x8180, std::uint16_t id = 0x1234) {
    Packet packet;
    append_u16_be(packet, id);
    append_u16_be(packet, flags);
    for (const auto count : counts) {
        append_u16_be(packet, count);
    }
    return packet;
}

/// 按大端顺序覆盖报文中的一个 16 位字段。
void set_word(Packet& packet, std::size_t offset, std::uint16_t value) {
    packet[offset] = static_cast<std::byte>((value >> 8) & 0xffU);
    packet[offset + 1] = static_cast<std::byte>(value & 0xffU);
}

/// 追加给定名称、类型和类别的问题条目。
void append_question(Packet& packet, std::span<const std::byte> name,
                     std::uint16_t type, std::uint16_t qclass) {
    packet.insert(packet.end(), name.begin(), name.end());
    append_u16_be(packet, type);
    append_u16_be(packet, qclass);
}

/// 使用给定字段和原始 RDATA 追加一条资源记录。
void append_record(Packet& packet, std::uint16_t type, std::uint16_t rr_class,
                   std::span<const std::byte> rdata, std::uint32_t ttl = 0,
                   std::span<const std::byte> owner = root_name) {
    REQUIRE(rdata.size() <= 65535);
    packet.insert(packet.end(), owner.begin(), owner.end());
    append_u16_be(packet, type);
    append_u16_be(packet, rr_class);
    append_u32_be(packet, ttl);
    append_u16_be(packet, static_cast<std::uint16_t>(rdata.size()));
    packet.insert(packet.end(), rdata.begin(), rdata.end());
}

/// 断言报文解析失败，并检查错误类别及报文偏移。
void check_error(std::span<const std::byte> packet, DnsParseErrorCode code,
                 std::size_t offset) {
    const auto result = parse_message(packet);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().offset == offset);
}

TEST_CASE("报文解析解码完整的 A 响应基准报文",
          "[message_parser][golden]") {
    const auto packet = golden_response();
    const auto original = packet;
    const auto result = parse_message(packet);
    REQUIRE(result.has_value());
    CHECK(packet == original);
    CHECK(result->header.id == 0x1234);
    CHECK(result->header.flags == 0x8180);
    REQUIRE(result->questions.size() == 1);
    const std::vector<std::string> expected_name{"example", "com"};
    CHECK(result->questions[0].name.labels == expected_name);
    CHECK(result->questions[0].type == 1);
    CHECK(result->questions[0].qclass == 1);
    REQUIRE(result->answers.size() == 1);
    const auto& answer = result->answers[0];
    CHECK(answer.owner.labels == expected_name);
    CHECK(answer.type == 1);
    CHECK(answer.rr_class == 1);
    CHECK(answer.ttl == 300);
    REQUIRE(std::holds_alternative<AData>(answer.rdata));
    const std::array address{std::byte{93}, std::byte{184}, std::byte{216}, std::byte{34}};
    CHECK(std::get<AData>(answer.rdata).address == address);
    CHECK(result->authority.empty());
    CHECK(result->additional.empty());
}

TEST_CASE("十二字节报文保留标志且不执行响应匹配",
          "[message_parser][header]") {
    for (const std::uint16_t flags : {std::uint16_t{0}, std::uint16_t{0xffff},
                                      std::uint16_t{0x784f}}) {
        CAPTURE(flags);
        const auto result = parse_message(header({}, flags, 0xbeef));
        REQUIRE(result.has_value());
        CHECK(result->header.id == 0xbeef);
        CHECK(result->header.flags == flags);
        CHECK(result->questions.empty());
        CHECK(result->answers.empty());
        CHECK(result->authority.empty());
        CHECK(result->additional.empty());
    }
}

TEST_CASE("报文解析保留四个区段且不限制问题数量",
          "[message_parser][sections]") {
    auto packet = header({2, 1, 1, 1}, 0x7fff);
    append_question(packet, root_name, 0xffff, 0xfffe);
    const std::array root_pointer{std::byte{0xc0}, std::byte{12}};
    append_question(packet, root_pointer, 0x1234, 0x4321);
    const Packet opaque{std::byte{0xff}, std::byte{0xc0}, std::byte{0}};
    append_record(packet, 65000, 65535, opaque, 0xffffffffU);
    const std::array ipv4{std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1}};
    append_record(packet, 1, 1, ipv4);
    const std::array<std::byte, 16> ipv6{
        std::byte{0x20}, std::byte{0x01}, std::byte{0x0d}, std::byte{0xb8},
        std::byte{0}, std::byte{1}, std::byte{0}, std::byte{2},
        std::byte{0x80}, std::byte{0xff}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
    append_record(packet, 28, 1, ipv6, 0x80000000U);

    const auto result = parse_message(packet);
    REQUIRE(result.has_value());
    CHECK(result->header.flags == 0x7fff);
    REQUIRE(result->questions.size() == 2);
    CHECK(result->questions[0].name.labels.empty());
    CHECK(result->questions[0].type == 0xffff);
    CHECK(result->questions[0].qclass == 0xfffe);
    CHECK(result->questions[1].name.labels.empty());
    CHECK(result->questions[1].type == 0x1234);
    CHECK(result->questions[1].qclass == 0x4321);
    REQUIRE(result->answers.size() == 1);
    REQUIRE(result->authority.size() == 1);
    REQUIRE(result->additional.size() == 1);
    CHECK(result->answers[0].type == 65000);
    CHECK(result->answers[0].rr_class == 65535);
    CHECK(result->answers[0].ttl == 0xffffffffU);
    REQUIRE(std::holds_alternative<OpaqueData>(result->answers[0].rdata));
    CHECK(std::get<OpaqueData>(result->answers[0].rdata).bytes == opaque);
    REQUIRE(std::holds_alternative<AData>(result->authority[0].rdata));
    CHECK(std::get<AData>(result->authority[0].rdata).address == ipv4);
    CHECK(result->authority[0].ttl == 0);
    REQUIRE(std::holds_alternative<AaaaData>(result->additional[0].rdata));
    CHECK(std::get<AaaaData>(result->additional[0].rdata).address == ipv6);
    CHECK(result->additional[0].ttl == 0x80000000U);
}

TEST_CASE("CNAME 解码使用完整报文并正确累计压缩消费长度",
          "[message_parser][cname]") {
    auto packet = golden_response();
    packet.resize(29); // 只保留报文头和 example.com 问题。
    set_word(packet, 6, 2);
    const std::array owner{std::byte{0xc0}, std::byte{12}};
    const std::array alias{
        std::byte{3}, std::byte{'w'}, std::byte{'w'}, std::byte{'w'},
        std::byte{0xc0}, std::byte{12}};
    append_record(packet, 5, 3, alias, 60, owner);
    const std::array alias_owner{std::byte{0xc0}, std::byte{41}};
    const std::array address{std::byte{192}, std::byte{0}, std::byte{2}, std::byte{7}};
    append_record(packet, 1, 1, address, 30, alias_owner);

    const auto result = parse_message(packet);
    REQUIRE(result.has_value());
    REQUIRE(result->answers.size() == 2);
    CHECK(result->answers[0].rr_class == 3); // 任意类别的 CNAME 都按名称数据解析。
    REQUIRE(std::holds_alternative<NameData>(result->answers[0].rdata));
    const std::vector<std::string> expected{"www", "example", "com"};
    CHECK(std::get<NameData>(result->answers[0].rdata).name.labels == expected);
    CHECK(result->answers[1].owner.labels == expected);
    REQUIRE(std::holds_alternative<AData>(result->answers[1].rdata));
    CHECK(std::get<AData>(result->answers[1].rdata).address == address);

    auto ordinary = header({0, 1, 0, 0});
    const std::array raw_name{std::byte{1}, std::byte{0xff}, std::byte{0}};
    append_record(ordinary, 5, 1, raw_name);
    const auto raw_result = parse_message(ordinary);
    REQUIRE(raw_result.has_value());
    REQUIRE(std::holds_alternative<NameData>(raw_result->answers[0].rdata));
    const std::vector<std::string> raw_labels{std::string(1, static_cast<char>(0xff))};
    CHECK(std::get<NameData>(raw_result->answers[0].rdata).name.labels == raw_labels);
}

TEST_CASE("未知类型和非 IN 地址记录保留原始数据",
          "[message_parser][opaque]") {
    struct Sample {
        std::uint16_t type;
        std::uint16_t rr_class;
        Packet bytes;
    };
    const std::array samples{
        Sample{1, 3, {std::byte{0xff}, std::byte{0xc0}}},
        Sample{28, 65535, {std::byte{1}}},
        Sample{65000, 1, {std::byte{0xc0}, std::byte{0xff}, std::byte{0}}},
        Sample{0, 0, {}},
    };
    for (const auto& sample : samples) {
        CAPTURE(sample.type, sample.rr_class);
        auto packet = header({0, 1, 0, 0});
        append_record(packet, sample.type, sample.rr_class, sample.bytes);
        const auto result = parse_message(packet);
        REQUIRE(result.has_value());
        REQUIRE(result->answers.size() == 1);
        REQUIRE(std::holds_alternative<OpaqueData>(result->answers[0].rdata));
        CHECK(std::get<OpaqueData>(result->answers[0].rdata).bytes == sample.bytes);
    }
}

TEST_CASE("报文解析拒绝基准响应的所有截断形式",
          "[message_parser][bounds]") {
    const auto packet = golden_response();
    REQUIRE(packet.size() == 45);
    const std::span<const std::byte> bytes{packet};
    for (std::size_t length = 0; length < 12; ++length) {
        CAPTURE(length);
        check_error(bytes.first(length), DnsParseErrorCode::PacketTooShort, length);
    }
    struct ExpectedRange {
        std::size_t first;
        std::size_t end;
        DnsParseErrorCode code;
        std::size_t offset;
    };
    const std::array ranges{
        ExpectedRange{12, 13, DnsParseErrorCode::SectionCountMismatch, 12},
        ExpectedRange{13, 20, DnsParseErrorCode::NameOutOfBounds, 12},
        ExpectedRange{20, 24, DnsParseErrorCode::NameOutOfBounds, 20},
        ExpectedRange{24, 25, DnsParseErrorCode::NameOutOfBounds, 24},
        ExpectedRange{25, 27, DnsParseErrorCode::FieldOutOfBounds, 25},
        ExpectedRange{27, 29, DnsParseErrorCode::FieldOutOfBounds, 27},
        ExpectedRange{29, 30, DnsParseErrorCode::SectionCountMismatch, 29},
        ExpectedRange{30, 31, DnsParseErrorCode::CompressionPointerTruncated, 29},
        ExpectedRange{31, 33, DnsParseErrorCode::FieldOutOfBounds, 31},
        ExpectedRange{33, 35, DnsParseErrorCode::FieldOutOfBounds, 33},
        ExpectedRange{35, 39, DnsParseErrorCode::FieldOutOfBounds, 35},
        ExpectedRange{39, 41, DnsParseErrorCode::FieldOutOfBounds, 39},
        ExpectedRange{41, 45, DnsParseErrorCode::FieldOutOfBounds, 41},
    };
    for (const auto& range : ranges) {
        for (auto length = range.first; length < range.end; ++length) {
            CAPTURE(length);
            check_error(bytes.first(length), range.code, range.offset);
        }
    }
}

TEST_CASE("各区段计数在首个缺失条目处报错",
          "[message_parser][counts]") {
    for (std::size_t section = 0; section < 4; ++section) {
        CAPTURE(section);
        std::array<std::uint16_t, 4> counts{};
        counts[section] = 65535;
        check_error(header(counts), DnsParseErrorCode::SectionCountMismatch, 12);

        counts[section] = 2;
        auto packet = header(counts);
        if (section == 0) {
            append_question(packet, root_name, 1, 1);
        } else {
            append_record(packet, 65000, 1, {});
        }
        check_error(packet, DnsParseErrorCode::SectionCountMismatch, packet.size());
    }
}

TEST_CASE("IN 地址记录拒绝完整但长度错误的 RDATA",
          "[message_parser][rdata]") {
    struct Sample {
        std::uint16_t type;
        std::size_t length;
    };
    for (const auto sample : {Sample{1, 0}, Sample{1, 3}, Sample{1, 5},
                               Sample{28, 0}, Sample{28, 15}, Sample{28, 17}}) {
        CAPTURE(sample.type, sample.length);
        auto packet = header({0, 1, 0, 0});
        append_record(packet, sample.type, 1, Packet(sample.length, std::byte{0}));
        check_error(packet, DnsParseErrorCode::InvalidRdataLength, 21);
    }
}

TEST_CASE("RDATA 先检查报文边界再检查类型长度",
          "[message_parser][rdata][bounds]") {
    for (const auto type : {std::uint16_t{1}, std::uint16_t{28},
                            std::uint16_t{5}, std::uint16_t{65000}}) {
        CAPTURE(type);
        auto packet = header({0, 1, 0, 0});
        const std::array bytes{std::byte{0}, std::byte{0}, std::byte{0}};
        append_record(packet, type, 1, bytes);
        set_word(packet, 21, 65535);
        check_error(packet, DnsParseErrorCode::FieldOutOfBounds, 23);
    }
}

TEST_CASE("CNAME 的 RDLENGTH 必须匹配消费长度且不能借用下一记录",
          "[message_parser][cname][bounds]") {
    SECTION("过短的 RDATA 不能借用下一记录的首字节") {
        auto packet = header({0, 2, 0, 0}, 0x8180, 0);
        const std::array incomplete_pointer{std::byte{0xc0}};
        append_record(packet, 5, 1, incomplete_pointer);
        append_record(packet, 65000, 1, {});
        // 后续记录的根名本可补齐指向报文首字节的压缩指针。
        check_error(packet, DnsParseErrorCode::RdataLengthMismatch, 23);
    }
    SECTION("完整压缩指针不能在 RDATA 内留下多余字节") {
        auto packet = header({0, 1, 0, 0});
        const std::array padded_pointer{std::byte{0xc0}, std::byte{12}, std::byte{0xff}};
        append_record(packet, 5, 1, padded_pointer);
        check_error(packet, DnsParseErrorCode::RdataLengthMismatch, 23);
    }
    SECTION("普通根名也不能在 RDATA 内留下多余字节") {
        auto packet = header({0, 1, 0, 0});
        const std::array padded_root{std::byte{0}, std::byte{0}};
        append_record(packet, 5, 1, padded_root);
        check_error(packet, DnsParseErrorCode::RdataLengthMismatch, 23);
    }
}

TEST_CASE("报文解析原样传递名称错误及其相对报文偏移",
          "[message_parser][cname][errors]") {
    struct Sample {
        Packet bytes;
        DnsParseErrorCode code;
        std::size_t offset;
    };
    const std::array samples{
        Sample{{}, DnsParseErrorCode::NameOutOfBounds, 23},
        Sample{{std::byte{0x40}}, DnsParseErrorCode::ReservedLabelEncoding, 23},
        Sample{{std::byte{0xc0}}, DnsParseErrorCode::CompressionPointerTruncated, 23},
        Sample{{std::byte{0xc0}, std::byte{0xff}},
               DnsParseErrorCode::CompressionPointerOutOfBounds, 23},
        Sample{{std::byte{0xc0}, std::byte{25}, std::byte{0}},
               DnsParseErrorCode::CompressionPointerNotBackward, 23},
        Sample{{std::byte{1}, std::byte{'a'}, std::byte{0xc0}, std::byte{23}},
               DnsParseErrorCode::CompressionLoop, 23},
    };
    for (const auto& sample : samples) {
        CAPTURE(sample.bytes.size());
        auto packet = header({0, 1, 0, 0});
        append_record(packet, 5, 1, sample.bytes);
        check_error(packet, sample.code, sample.offset);
    }

    auto packet = header({0, 1, 0, 0}, 0x4080);
    const std::array invalid_target{std::byte{0xc0}, std::byte{2}};
    append_record(packet, 5, 1, invalid_target);
    check_error(packet, DnsParseErrorCode::ReservedLabelEncoding, 2);
}

TEST_CASE("报文解析接受 65535 字节并优先拒绝更大的报文",
          "[message_parser][bounds]") {
    auto packet = header({0, 1, 0, 0});
    const Packet opaque(65535 - 23, std::byte{0xff});
    append_record(packet, 65000, 1, opaque);
    REQUIRE(packet.size() == 65535);
    const auto result = parse_message(packet);
    REQUIRE(result.has_value());
    REQUIRE(result->answers.size() == 1);
    REQUIRE(std::holds_alternative<OpaqueData>(result->answers[0].rdata));
    CHECK(std::get<OpaqueData>(result->answers[0].rdata).bytes == opaque);

    packet.push_back(std::byte{0});
    check_error(packet, DnsParseErrorCode::PacketTooLarge, 65535);
}

TEST_CASE("报文解析拒绝声明区段之后的尾随字节",
          "[message_parser][bounds]") {
    auto empty = header({});
    empty.push_back(std::byte{0});
    check_error(empty, DnsParseErrorCode::TrailingData, 12);

    auto packet = golden_response();
    packet.push_back(std::byte{0xc0});
    packet.push_back(std::byte{0xff});
    check_error(packet, DnsParseErrorCode::TrailingData, 45);
}

} // 命名空间
