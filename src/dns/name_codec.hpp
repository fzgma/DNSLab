#pragma once

#include "dns/errors.hpp"
#include "dns/types.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace dnslab::dns {

// Accepts ASCII hostname labels and an optional trailing dot; "." is the root.
[[nodiscard]] std::expected<DnsName, NameInputError>
parse_ascii_name(std::string_view input);

// Validates label and wire lengths, preserving arbitrary label octets.
[[nodiscard]] std::expected<EncodedName, DnsEncodeError>
encode_name(const DnsName& name);

// Decodes ordinary labels only, stopping at the root byte. Errors identify the
// offending length byte, or the requested cursor when that byte is missing.
[[nodiscard]] std::expected<DecodedName, DnsParseError>
decode_name(std::span<const std::byte> packet, std::size_t start);

[[nodiscard]] std::string format_name(const DnsName& name);

[[nodiscard]] bool names_equal_case_insensitive(const DnsName& a,
                                                const DnsName& b) noexcept;

} // namespace dnslab::dns
