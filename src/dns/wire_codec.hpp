#pragma once

#include "dns/errors.hpp"
#include "dns/types.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace dnslab::dns {

// Parses one complete DNS packet; compression offsets use the full packet.
[[nodiscard]] std::expected<DnsMessage, DnsParseError>
parse_message(std::span<const std::byte> packet);

// Encodes one IN A/AAAA question without name compression. Validation checks
// the name before the query type and class; the caller supplies the transaction ID.
[[nodiscard]] std::expected<Packet, DnsEncodeError>
encode_query(const DnsQuestion& question, std::uint16_t transaction_id,
             bool recursion_desired = true);

} // namespace dnslab::dns
