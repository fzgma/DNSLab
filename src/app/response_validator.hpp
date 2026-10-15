#pragma once

#include "dns/types.hpp"

#include <cstdint>
#include <expected>

namespace dnslab::app {

enum class ResponseMismatch {
    NotResponse,
    TransactionId,
    Opcode,
    QuestionCount,
    QuestionName,
    QuestionType,
    QuestionClass,
};

// Matches an already parsed response to a standard query, checking in enum order.
// Source endpoints and packet structure belong to other validation layers.
[[nodiscard]] std::expected<void, ResponseMismatch>
validate_response(const dns::DnsMessage& response, const dns::DnsQuestion& question,
                  std::uint16_t transaction_id) noexcept;

} // namespace dnslab::app
