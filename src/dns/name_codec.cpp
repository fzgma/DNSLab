#include "dns/name_codec.hpp"

#include <unordered_set>
#include <utility>

namespace dnslab::dns {
namespace {

constexpr std::size_t max_label_length = 63;
constexpr std::size_t max_wire_length = 255;

/// 判断字节是否为允许出现在主机名中的 ASCII 字母或数字。
constexpr bool is_ascii_alphanumeric(unsigned char value) noexcept {
    return (value >= 'A' && value <= 'Z') ||
           (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9');
}

/// 仅将 ASCII 大写字母折叠为小写，保持其他字节不变。
constexpr unsigned char fold_ascii(unsigned char value) noexcept {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<unsigned char>(value + ('a' - 'A'));
    }
    return value;
}

} // 命名空间

/// 按标签校验查询名称，并保留原输入的字母大小写。
std::expected<DnsName, NameInputError>
parse_ascii_name(std::string_view input) {
    if (input.empty()) {
        return std::unexpected(NameInputError{NameInputErrorCode::EmptyName, 0});
    }
    if (input == ".") {
        return DnsName{};
    }

    DnsName name;
    std::size_t wire_length = 1; // 预留末尾根标签的一个字节。
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
    if (input.find_first_not_of("0123456789.") == std::string_view::npos) {
        return std::unexpected(NameInputError{NameInputErrorCode::NumericOnlyName, 0});
    }
    return name;
}

/// 预检全部标签长度后，将名称写为不使用压缩的 DNS 字节序列。
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

/// 迭代展开名称与压缩指针，并分别维护展开长度和原路径消费长度。
std::expected<DecodedName, DnsParseError>
decode_name(std::span<const std::byte> packet, std::size_t start) {
    DnsName name;
    std::size_t cursor = start;
    std::size_t consumed = 0;
    std::size_t expanded_wire_length = 1;
    bool jumped = false;
    std::unordered_set<std::size_t> visited;

    for (;;) {
        if (cursor >= packet.size()) {
            return std::unexpected(DnsParseError{DnsParseErrorCode::NameOutOfBounds, cursor});
        }
        // 普通标签也可能重新进入既有路径，因此每次读取前都检查访问记录。
        if (!visited.insert(cursor).second) {
            return std::unexpected(DnsParseError{DnsParseErrorCode::CompressionLoop, cursor});
        }
        const auto length = std::to_integer<unsigned char>(packet[cursor]);
        const auto encoding = length & 0xc0U;
        if (encoding == 0xc0U) {
            if (packet.size() - cursor < 2) {
                return std::unexpected(DnsParseError{
                    DnsParseErrorCode::CompressionPointerTruncated, cursor});
            }
            const std::size_t target = ((length & 0x3fU) << 8) |
                std::to_integer<unsigned char>(packet[cursor + 1]);
            if (target >= packet.size()) {
                return std::unexpected(DnsParseError{
                    DnsParseErrorCode::CompressionPointerOutOfBounds, cursor});
            }
            if (target >= cursor) {
                return std::unexpected(DnsParseError{
                    DnsParseErrorCode::CompressionPointerNotBackward, cursor});
            }
            // 跳转目标不占原字段长度，只有第一个指针计入 consumed。
            if (!jumped) {
                consumed += 2;
            }
            jumped = true;
            cursor = target;
            continue;
        }
        if (encoding != 0) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::ReservedLabelEncoding, cursor});
        }
        if (length == 0) {
            if (!jumped) {
                ++consumed;
            }
            return DecodedName{std::move(name), consumed};
        }

        // 已确认游标位于报文内，先减去长度字节可安全检查剩余空间。
        if (length > packet.size() - cursor - 1) {
            return std::unexpected(DnsParseError{DnsParseErrorCode::NameOutOfBounds, cursor});
        }
        const auto encoded_length = std::size_t{1} + length;
        if (encoded_length > max_wire_length - expanded_wire_length) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::ExpandedNameTooLong, cursor});
        }

        std::string label;
        label.reserve(length);
        for (const auto value : packet.subspan(cursor + 1, length)) {
            label.push_back(static_cast<char>(std::to_integer<unsigned char>(value)));
        }
        name.labels.push_back(std::move(label));
        expanded_wire_length += encoded_length;
        if (!jumped) {
            consumed += encoded_length;
        }
        cursor += encoded_length;
    }
}

/// 将标签格式化为带尾点的可显示名称，并转义点、反斜线和不可打印字节。
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

/// 保持标签边界不变，仅按 ASCII 大小写折叠比较两个名称。
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

} // 命名空间 dnslab::dns
