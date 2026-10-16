#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace dnslab::dns {

inline constexpr std::string_view query_type_choices = "A|AAAA|CNAME|MX|TXT|NS|SOA|PTR";

struct QueryTypeDefinition {
    std::uint16_t value;
    std::string_view name;
};

inline constexpr std::array query_types{
    QueryTypeDefinition{1, "A"}, QueryTypeDefinition{28, "AAAA"},
    QueryTypeDefinition{5, "CNAME"}, QueryTypeDefinition{15, "MX"},
    QueryTypeDefinition{16, "TXT"}, QueryTypeDefinition{2, "NS"},
    QueryTypeDefinition{6, "SOA"}, QueryTypeDefinition{12, "PTR"},
};

/// 查找支持直接查询的类型名称，未知数值返回空视图。
[[nodiscard]] constexpr std::string_view query_type_name(std::uint16_t type) noexcept {
    for (const auto& entry : query_types) {
        if (entry.value == type) {
            return entry.name;
        }
    }
    return {};
}

/// 判断类型数值是否属于当前允许直接查询的八种记录。
[[nodiscard]] constexpr bool is_supported_query_type(std::uint16_t type) noexcept {
    return !query_type_name(type).empty();
}

/// 按 ASCII 大小写不敏感规则匹配类型名称，拒绝数字编号及额外字符。
[[nodiscard]] constexpr std::optional<std::uint16_t>
query_type_from_text(std::string_view text) noexcept {
    for (const auto& entry : query_types) {
        if (text.size() != entry.name.size()) {
            continue;
        }
        bool matches = true;
        for (std::size_t index = 0; index < text.size(); ++index) {
            const auto value = static_cast<unsigned char>(text[index]);
            const auto folded = value >= 'a' && value <= 'z'
                ? static_cast<unsigned char>(value - ('a' - 'A')) : value;
            if (folded != static_cast<unsigned char>(entry.name[index])) {
                matches = false;
                break;
            }
        }
        if (matches) {
            return entry.value;
        }
    }
    return std::nullopt;
}

} // 命名空间 dnslab::dns
