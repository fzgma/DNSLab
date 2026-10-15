#include "dns/name_codec.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace dnslab::dns;

Packet example_wire_name() {
    return {std::byte{0x07}, std::byte{0x65}, std::byte{0x78}, std::byte{0x61},
            std::byte{0x6D}, std::byte{0x70}, std::byte{0x6C}, std::byte{0x65},
            std::byte{0x03}, std::byte{0x63}, std::byte{0x6F}, std::byte{0x6D},
            std::byte{0x00}};
}

void check_bytes(const Packet& packet, std::span<const std::byte> expected) {
    REQUIRE(packet.size() == expected.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        CAPTURE(index);
        CHECK(std::to_integer<unsigned int>(packet[index]) ==
              std::to_integer<unsigned int>(expected[index]));
    }
}

void check_input_error(std::string_view input, NameInputErrorCode code,
                       std::size_t offset) {
    const auto result = parse_ascii_name(input);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().offset == offset);
}

void check_decode_error(std::span<const std::byte> packet, std::size_t start,
                        DnsParseErrorCode code, std::size_t offset) {
    const auto result = decode_name(packet, start);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().offset == offset);
}

TEST_CASE("ASCII name input preserves case and accepts a single trailing dot",
          "[name_codec][input]") {
    const std::vector<std::string> expected{"ExAmPlE", "COM"};
    for (const auto input : {"ExAmPlE.COM", "ExAmPlE.COM."}) {
        CAPTURE(input);
        const auto result = parse_ascii_name(input);
        REQUIRE(result.has_value());
        CHECK(result->labels == expected);
    }
}

TEST_CASE("ASCII name input accepts numeric labels and existing Punycode",
          "[name_codec][input]") {
    struct Sample {
        std::string_view input;
        std::vector<std::string> labels;
    };
    const std::array samples{
        Sample{"A0-z.xn--bcher-kva.42", {"A0-z", "xn--bcher-kva", "42"}},
        Sample{"123.example", {"123", "example"}},
        Sample{"a.123.", {"a", "123"}},
        Sample{"1-2", {"1-2"}},
    };

    for (const auto& sample : samples) {
        CAPTURE(sample.input);
        const auto result = parse_ascii_name(sample.input);
        REQUIRE(result.has_value());
        CHECK(result->labels == sample.labels);
    }
}

TEST_CASE("ASCII query names reject inputs made only of digits and dots",
          "[name_codec][input]") {
    for (const auto input : {"0", "0.", "123", "123.", "1.2.3", "1.2.3.",
                             "1.2.3.4", "1.2.3.4.", "999.1.1.1", "999.1.1.1."}) {
        CAPTURE(input);
        check_input_error(input, NameInputErrorCode::NumericOnlyName, 0);
    }
}

TEST_CASE("Numeric query names still report syntax and length errors first",
          "[name_codec][input][bounds]") {
    check_input_error("1..2", NameInputErrorCode::EmptyLabel, 2);
    check_input_error("123 ", NameInputErrorCode::InvalidCharacter, 3);
    check_input_error(std::string(63, '1'), NameInputErrorCode::NumericOnlyName, 0);
    check_input_error(std::string(64, '1'), NameInputErrorCode::LabelTooLong, 0);

    const std::string prefix = std::string(63, '1') + "." +
                               std::string(63, '2') + "." +
                               std::string(63, '3') + ".";
    check_input_error(prefix + std::string(61, '4'),
                      NameInputErrorCode::NumericOnlyName, 0);
    check_input_error(prefix + std::string(62, '4'),
                      NameInputErrorCode::NameTooLong, 192);
}

TEST_CASE("The root name has no labels and a one-byte wire representation",
          "[name_codec][input][encode][decode][format]") {
    const auto parsed = parse_ascii_name(".");
    REQUIRE(parsed.has_value());
    CHECK(parsed->labels.empty());

    const auto encoded = encode_name(DnsName{});
    REQUIRE(encoded.has_value());
    const std::array expected{std::byte{0x00}};
    check_bytes(encoded->bytes, expected);

    const auto decoded = decode_name(expected, 0);
    REQUIRE(decoded.has_value());
    CHECK(decoded->name.labels.empty());
    CHECK(decoded->consumed == 1);
    CHECK(format_name(DnsName{}) == ".");
}

TEST_CASE("ASCII name input rejects empty names and empty labels",
          "[name_codec][input][bounds]") {
    check_input_error("", NameInputErrorCode::EmptyName, 0);
    check_input_error(".example", NameInputErrorCode::EmptyLabel, 0);
    check_input_error("..", NameInputErrorCode::EmptyLabel, 0);
    check_input_error("a..b", NameInputErrorCode::EmptyLabel, 2);
    check_input_error("a..", NameInputErrorCode::EmptyLabel, 2);
    check_input_error("example.com..", NameInputErrorCode::EmptyLabel, 12);
}

TEST_CASE("ASCII name input rejects invalid bytes at their original offsets",
          "[name_codec][input]") {
    struct Sample {
        std::string input;
        std::size_t offset;
    };
    const std::array samples{
        Sample{" a", 0}, Sample{"a ", 1}, Sample{"a\tb", 1},
        Sample{"a\nb", 1}, Sample{"a\rb", 1}, Sample{"a_b", 1},
        Sample{"a\\046b", 1}, Sample{"a\x1B" "b", 1}, Sample{"a\x7F" "b", 1},
        Sample{"https://example.com", 5}, Sample{"example.com:53", 11},
        Sample{"user@example.com", 4}, Sample{"example.com/path", 11},
        Sample{"2001:db8::1", 4}, Sample{"[2001:db8::1]", 0},
        Sample{std::string{"ab\0cd", 5}, 2},
        Sample{std::string{"ex\xC3\xA9.com"}, 2},
        Sample{std::string{"a"} + static_cast<char>(0xFF), 1},
        Sample{"example\xEF\xBC\x8E" "com", 7}, // U+FF0E fullwidth full stop.
        Sample{"\xEF\xBC\xA1" ".example", 0}, // U+FF21 fullwidth A.
        Sample{"ex\xE2\x80\x8B" "ample.com", 2}, // U+200B zero width space.
        Sample{"a\xC2\xA0" "b", 1}, // U+00A0 no-break space.
    };

    for (const auto& sample : samples) {
        CAPTURE(sample.input, sample.offset);
        check_input_error(sample.input, NameInputErrorCode::InvalidCharacter,
                          sample.offset);
    }
}

TEST_CASE("ASCII name input rejects leading and trailing hyphens",
          "[name_codec][input]") {
    check_input_error("-", NameInputErrorCode::HyphenAtBoundary, 0);
    check_input_error("-abc", NameInputErrorCode::HyphenAtBoundary, 0);
    check_input_error("abc-", NameInputErrorCode::HyphenAtBoundary, 3);
    check_input_error("a.-b", NameInputErrorCode::HyphenAtBoundary, 2);
    check_input_error("a.b-.", NameInputErrorCode::HyphenAtBoundary, 3);
}

TEST_CASE("ASCII name input enforces the 63-byte label limit",
          "[name_codec][input][bounds]") {
    const std::string valid_label(63, 'a');
    const auto valid = parse_ascii_name(valid_label);
    REQUIRE(valid.has_value());
    REQUIRE(valid->labels.size() == 1);
    CHECK(valid->labels.front() == valid_label);

    check_input_error(std::string(64, 'a'), NameInputErrorCode::LabelTooLong, 0);
    check_input_error("ok." + std::string(64, 'a'),
                      NameInputErrorCode::LabelTooLong, 3);
}

TEST_CASE("ASCII name input counts label lengths and the root in the 255-byte limit",
          "[name_codec][input][bounds]") {
    const std::string prefix = std::string(63, 'a') + "." +
                               std::string(63, 'b') + "." +
                               std::string(63, 'c') + ".";
    const std::vector<std::string> expected{
        std::string(63, 'a'), std::string(63, 'b'),
        std::string(63, 'c'), std::string(61, 'd')};

    for (const auto& input : {prefix + std::string(61, 'd'),
                              prefix + std::string(61, 'd') + "."}) {
        const auto result = parse_ascii_name(input);
        REQUIRE(result.has_value());
        CHECK(result->labels == expected);
    }

    check_input_error(prefix + std::string(62, 'd'),
                      NameInputErrorCode::NameTooLong, 192);
    check_input_error(prefix + std::string(62, 'd') + ".",
                      NameInputErrorCode::NameTooLong, 192);
}

TEST_CASE("Name encoding matches the example.com golden wire bytes",
          "[name_codec][encode]") {
    const DnsName name{{"example", "com"}};
    const auto result = encode_name(name);
    REQUIRE(result.has_value());
    check_bytes(result->bytes, example_wire_name());

    for (const auto input : {"example.com", "example.com."}) {
        const auto parsed = parse_ascii_name(input);
        REQUIRE(parsed.has_value());
        const auto encoded = encode_name(*parsed);
        REQUIRE(encoded.has_value());
        check_bytes(encoded->bytes, example_wire_name());
    }
}

TEST_CASE("Numeric wire names remain valid independently of query input rules",
          "[name_codec][encode][decode]") {
    const DnsName name{{"1", "2", "3", "4"}};
    const Packet wire{std::byte{1}, std::byte{0x31}, std::byte{1}, std::byte{0x32},
                      std::byte{1}, std::byte{0x33}, std::byte{1}, std::byte{0x34},
                      std::byte{0}};

    const auto encoded = encode_name(name);
    REQUIRE(encoded.has_value());
    check_bytes(encoded->bytes, wire);

    const auto decoded = decode_name(wire, 0);
    REQUIRE(decoded.has_value());
    CHECK(decoded->name.labels == name.labels);
    CHECK(decoded->consumed == 9);
    CHECK(format_name(decoded->name) == "1.2.3.4.");
}

TEST_CASE("Name encoding validates labels supplied without the input parser",
          "[name_codec][encode][bounds]") {
    struct Sample {
        DnsName name;
        DnsEncodeErrorCode code;
        std::size_t label_index;
    };
    const std::array samples{
        Sample{DnsName{{""}}, DnsEncodeErrorCode::EmptyLabel, 0},
        Sample{DnsName{{"ok", "", "com"}}, DnsEncodeErrorCode::EmptyLabel, 1},
        Sample{DnsName{{std::string(64, 'a')}}, DnsEncodeErrorCode::LabelTooLong, 0},
        Sample{DnsName{{"ok", std::string(64, 'a')}},
               DnsEncodeErrorCode::LabelTooLong, 1},
        Sample{DnsName{{std::string(63, 'a'), std::string(63, 'b'),
                        std::string(63, 'c'), std::string(62, 'd')}},
               DnsEncodeErrorCode::NameTooLong, 3},
    };

    for (const auto& sample : samples) {
        CAPTURE(sample.label_index);
        const auto result = encode_name(sample.name);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == sample.code);
        CHECK(result.error().label_index == sample.label_index);
    }
}

TEST_CASE("Name encoding accepts exactly 255 wire bytes",
          "[name_codec][encode][bounds]") {
    const DnsName name{{std::string(63, 'a'), std::string(63, 'a'),
                        std::string(63, 'a'), std::string(61, 'a')}};
    Packet expected(255, std::byte{0x61});
    expected[0] = std::byte{63};
    expected[64] = std::byte{63};
    expected[128] = std::byte{63};
    expected[192] = std::byte{61};
    expected[254] = std::byte{0};

    const auto result = encode_name(name);
    REQUIRE(result.has_value());
    check_bytes(result->bytes, expected);
}

TEST_CASE("Ordinary name decoding matches the golden wire bytes",
          "[name_codec][decode]") {
    const auto result = decode_name(example_wire_name(), 0);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{"example", "com"};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 13);
}

TEST_CASE("Ordinary name decoding honors offsets and stops after the root byte",
          "[name_codec][decode]") {
    Packet packet{std::byte{0xAA}, std::byte{0xBB}};
    const auto wire_name = example_wire_name();
    packet.insert(packet.end(), wire_name.begin(), wire_name.end());
    packet.push_back(std::byte{0xFF});
    const auto original = packet;

    const auto result = decode_name(packet, 2);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{"example", "com"};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 13);
    CHECK(packet == original);

    const auto root = decode_name(packet, 14);
    REQUIRE(root.has_value());
    CHECK(root->name.labels.empty());
    CHECK(root->consumed == 1);
}

TEST_CASE("Ordinary name decoding accepts the 63-byte label boundary",
          "[name_codec][decode][bounds]") {
    Packet packet(65, std::byte{0x61});
    packet.front() = std::byte{63};
    packet.back() = std::byte{0};

    const auto result = decode_name(packet, 0);
    REQUIRE(result.has_value());
    REQUIRE(result->name.labels.size() == 1);
    CHECK(result->name.labels.front() == std::string(63, 'a'));
    CHECK(result->consumed == 65);
}

TEST_CASE("Ordinary name decoding enforces the expanded 255-byte limit",
          "[name_codec][decode][bounds]") {
    Packet valid(255, std::byte{0x61});
    valid[0] = std::byte{63};
    valid[64] = std::byte{63};
    valid[128] = std::byte{63};
    valid[192] = std::byte{61};
    valid[254] = std::byte{0};
    const auto result = decode_name(valid, 0);
    REQUIRE(result.has_value());
    const std::vector<std::string> expected{
        std::string(63, 'a'), std::string(63, 'a'),
        std::string(63, 'a'), std::string(61, 'a')};
    CHECK(result->name.labels == expected);
    CHECK(result->consumed == 255);

    Packet invalid(256, std::byte{0x61});
    invalid[0] = std::byte{63};
    invalid[64] = std::byte{63};
    invalid[128] = std::byte{63};
    invalid[192] = std::byte{62};
    invalid[255] = std::byte{0};
    check_decode_error(invalid, 0, DnsParseErrorCode::ExpandedNameTooLong, 192);
}

TEST_CASE("Ordinary name decoding rejects every truncation of a golden name",
          "[name_codec][decode][bounds]") {
    const auto packet = example_wire_name();
    const std::span<const std::byte> bytes{packet};
    // Offsets name the incomplete label, or the missing next length byte.
    constexpr std::array<std::size_t, 13> expected_offsets{
        0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 12};

    for (std::size_t length = 0; length < expected_offsets.size(); ++length) {
        CAPTURE(length);
        check_decode_error(bytes.first(length), 0,
                           DnsParseErrorCode::NameOutOfBounds,
                           expected_offsets[length]);
    }

    const Packet offset_packet{std::byte{0xAA}, std::byte{0x03}, std::byte{0x61}};
    check_decode_error(offset_packet, 1, DnsParseErrorCode::NameOutOfBounds, 1);
}

TEST_CASE("Ordinary name decoding rejects invalid start offsets without overflow",
          "[name_codec][decode][bounds]") {
    const Packet packet{std::byte{0x00}};
    constexpr auto maximum = std::numeric_limits<std::size_t>::max();
    for (const auto offset : {std::size_t{1}, std::size_t{2}, maximum - 1, maximum}) {
        CAPTURE(offset);
        check_decode_error(packet, offset, DnsParseErrorCode::NameOutOfBounds, offset);
        check_decode_error({}, offset, DnsParseErrorCode::NameOutOfBounds, offset);
    }
    check_decode_error({}, 0, DnsParseErrorCode::NameOutOfBounds, 0);
}

TEST_CASE("Ordinary name decoding rejects reserved label encodings",
          "[name_codec][decode]") {
    for (const auto marker : {0x40, 0x7F, 0x80, 0xBF}) {
        CAPTURE(marker);
        const Packet packet{std::byte{0xAA}, static_cast<std::byte>(marker),
                            std::byte{0x00}};
        check_decode_error(packet, 1, DnsParseErrorCode::ReservedLabelEncoding, 1);
    }
}

TEST_CASE("Wire names preserve arbitrary label octets and format them safely",
          "[name_codec][encode][decode][format]") {
    const std::string label{
        '\0', '\t', '\n', static_cast<char>(0x1F), ' ', '.', '\\',
        static_cast<char>(0x7F), static_cast<char>(0x80), static_cast<char>(0xFF), 'A'};
    const Packet wire{
        std::byte{11}, std::byte{0}, std::byte{9}, std::byte{10}, std::byte{31},
        std::byte{32}, std::byte{46}, std::byte{92}, std::byte{127}, std::byte{128},
        std::byte{255}, std::byte{65}, std::byte{0}};

    const auto decoded = decode_name(wire, 0);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->name.labels.size() == 1);
    CHECK(decoded->name.labels.front() == label);
    CHECK(decoded->consumed == 13);

    const auto encoded = encode_name(DnsName{{label}});
    REQUIRE(encoded.has_value());
    check_bytes(encoded->bytes, wire);
    CHECK(format_name(DnsName{{label}}) ==
          "\\000\\009\\010\\031\\032\\046\\092\\127\\128\\255A.");
}

TEST_CASE("Name formatting preserves printable characters and label boundaries",
          "[name_codec][format]") {
    CHECK(format_name(DnsName{{"ExAmPlE", "COM"}}) == "ExAmPlE.COM.");
    CHECK(format_name(DnsName{{"A-z_!~"}}) == "A-z_!~.");
    CHECK(format_name(DnsName{{"a.b", "c\\d"}}) == "a\\046b.c\\092d.");
    CHECK(format_name(DnsName{{"a", "b"}}) == "a.b.");
}

TEST_CASE("Name comparison folds only ASCII letters",
          "[name_codec][compare]") {
    const DnsName uppercase{{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ExAmPlE"}};
    const DnsName lowercase{{"abcdefghijklmnopqrstuvwxyz", "example"}};
    CHECK(names_equal_case_insensitive(uppercase, lowercase));
    CHECK(names_equal_case_insensitive(lowercase, uppercase));
    CHECK(names_equal_case_insensitive(DnsName{}, DnsName{}));
    CHECK_FALSE(names_equal_case_insensitive(DnsName{}, DnsName{{"a"}}));
    CHECK_FALSE(names_equal_case_insensitive(DnsName{{"@"}}, DnsName{{"`"}}));
    CHECK_FALSE(names_equal_case_insensitive(DnsName{{"["}}, DnsName{{"{"}}));

    const std::string high_upper{static_cast<char>(0xC0), 'A', '\0'};
    const std::string high_same{static_cast<char>(0xC0), 'a', '\0'};
    const std::string high_different{static_cast<char>(0xE0), 'a', '\0'};
    CHECK(names_equal_case_insensitive(DnsName{{high_upper}}, DnsName{{high_same}}));
    CHECK_FALSE(names_equal_case_insensitive(DnsName{{high_upper}},
                                            DnsName{{high_different}}));
}

TEST_CASE("Name comparison preserves label boundaries and bytes after NUL",
          "[name_codec][compare]") {
    CHECK_FALSE(names_equal_case_insensitive(DnsName{{"ab", "c"}},
                                            DnsName{{"a", "bc"}}));
    CHECK_FALSE(names_equal_case_insensitive(DnsName{{"a.b"}}, DnsName{{"a", "b"}}));
    CHECK_FALSE(names_equal_case_insensitive(DnsName{{"a"}}, DnsName{{"a", "b"}}));

    const std::string first{"a\0b", 3};
    const std::string second{"A\0c", 3};
    CHECK_FALSE(names_equal_case_insensitive(DnsName{{first}}, DnsName{{second}}));
}

} // namespace
