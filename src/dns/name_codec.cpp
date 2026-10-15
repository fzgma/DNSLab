#include "dns/name_codec.hpp"

#include <utility>

namespace dnslab::dns {
namespace {

constexpr std::size_t max_label_length = 63;
constexpr std::size_t max_wire_length = 255;

constexpr bool is_ascii_alphanumeric(unsigned char value) noexcept {
    return (value >= 'A' && value <= 'Z') ||
           (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9');
}

constexpr unsigned char fold_ascii(unsigned char value) noexcept {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<unsigned char>(value + ('a' - 'A'));
    }
    return value;
}

} // namespace

std::expected<DnsName, NameInputError>
parse_ascii_name(std::string_view input) {
    if (input.empty()) {
        return std::unexpected(NameInputError{NameInputErrorCode::EmptyName, 0});
    }
    if (input == ".") {
        return DnsName{};
    }

    DnsName name;
    std::size_t wire_length = 1; // Reserve the terminating root byte.
    std::size_t label_start = 0;
    while (label_start < input.size()) {
        const auto dot = input.find('.', label_start);
        const auto label_end = dot == std::string_view::npos ? input.size() : dot;
        const auto label = input.substr(label_start, label_end - label_start);

        if (label.empty()) {
            return std::unexpected(NameInputError{NameInputErrorCode::EmptyLabel, label_start});
        }
        if (label.size() > max_label_length) {
            return std::unexpected(NameInputError{NameInputErrorCode::LabelTooLong, label_start});
        }
        if (label.size() + 1 > max_wire_length - wire_length) {
            return std::unexpected(NameInputError{NameInputErrorCode::NameTooLong, label_start});
        }

        for (std::size_t index = 0; index < label.size(); ++index) {
            const auto value = static_cast<unsigned char>(label[index]);
            if (value == '-') {
                if (index == 0 || index == label.size() - 1) {
                    return std::unexpected(NameInputError{
                        NameInputErrorCode::HyphenAtBoundary, label_start + index});
                }
            } else if (!is_ascii_alphanumeric(value)) {
                return std::unexpected(NameInputError{
                    NameInputErrorCode::InvalidCharacter, label_start + index});
            }
        }

        wire_length += label.size() + 1;
        name.labels.emplace_back(label);
        if (dot == std::string_view::npos || dot == input.size() - 1) {
            break;
        }
        label_start = dot + 1;
    }
    return name;
}

std::expected<EncodedName, DnsEncodeError> encode_name(const DnsName& name) {
    std::size_t wire_length = 1;
    for (std::size_t index = 0; index < name.labels.size(); ++index) {
        const auto& label = name.labels[index];
        if (label.empty()) {
            return std::unexpected(DnsEncodeError{DnsEncodeErrorCode::EmptyLabel, index});
        }
        if (label.size() > max_label_length) {
            return std::unexpected(DnsEncodeError{DnsEncodeErrorCode::LabelTooLong, index});
        }
        if (label.size() + 1 > max_wire_length - wire_length) {
            return std::unexpected(DnsEncodeError{DnsEncodeErrorCode::NameTooLong, index});
        }
        wire_length += label.size() + 1;
    }

    EncodedName encoded;
    encoded.bytes.reserve(wire_length);
    for (const auto& label : name.labels) {
        encoded.bytes.push_back(static_cast<std::byte>(label.size()));
        for (const char value : label) {
            encoded.bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
        }
    }
    encoded.bytes.push_back(std::byte{0});
    return encoded;
}

std::expected<DecodedName, DnsParseError>
decode_name(std::span<const std::byte> packet, std::size_t start) {
    DnsName name;
    std::size_t cursor = start;
    std::size_t wire_length = 1;

    for (;;) {
        if (cursor >= packet.size()) {
            return std::unexpected(DnsParseError{DnsParseErrorCode::NameOutOfBounds, cursor});
        }
        const auto length = std::to_integer<unsigned char>(packet[cursor]);
        const auto encoding = length & 0xc0U;
        if (encoding == 0xc0U) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::CompressionNotSupported, cursor});
        }
        if (encoding != 0) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::ReservedLabelEncoding, cursor});
        }
        if (length == 0) {
            ++cursor;
            return DecodedName{std::move(name), cursor - start};
        }

        // cursor is within packet, so subtracting its length byte is safe.
        if (length > packet.size() - cursor - 1) {
            return std::unexpected(DnsParseError{DnsParseErrorCode::NameOutOfBounds, cursor});
        }
        const auto encoded_length = std::size_t{1} + length;
        if (encoded_length > max_wire_length - wire_length) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::ExpandedNameTooLong, cursor});
        }

        std::string label;
        label.reserve(length);
        for (const auto value : packet.subspan(cursor + 1, length)) {
            label.push_back(static_cast<char>(std::to_integer<unsigned char>(value)));
        }
        name.labels.push_back(std::move(label));
        wire_length += encoded_length;
        cursor += encoded_length;
    }
}

std::string format_name(const DnsName& name) {
    if (name.labels.empty()) {
        return ".";
    }

    std::string result;
    for (const auto& label : name.labels) {
        for (const char character : label) {
            const auto value = static_cast<unsigned char>(character);
            if (value >= 0x21 && value <= 0x7e && value != '.' && value != '\\') {
                result.push_back(character);
            } else {
                result.push_back('\\');
                result.push_back(static_cast<char>('0' + value / 100));
                result.push_back(static_cast<char>('0' + (value / 10) % 10));
                result.push_back(static_cast<char>('0' + value % 10));
            }
        }
        result.push_back('.');
    }
    return result;
}

bool names_equal_case_insensitive(const DnsName& a, const DnsName& b) noexcept {
    if (a.labels.size() != b.labels.size()) {
        return false;
    }
    for (std::size_t label_index = 0; label_index < a.labels.size(); ++label_index) {
        const auto& first = a.labels[label_index];
        const auto& second = b.labels[label_index];
        if (first.size() != second.size()) {
            return false;
        }
        for (std::size_t index = 0; index < first.size(); ++index) {
            if (fold_ascii(static_cast<unsigned char>(first[index])) !=
                fold_ascii(static_cast<unsigned char>(second[index]))) {
                return false;
            }
        }
    }
    return true;
}

} // namespace dnslab::dns
