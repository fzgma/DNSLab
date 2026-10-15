#include "app/response_validator.hpp"

#include "dns/name_codec.hpp"

namespace dnslab::app {

std::expected<void, ResponseMismatch>
validate_response(const dns::DnsMessage& response, const dns::DnsQuestion& question,
                  std::uint16_t transaction_id) noexcept {
    if (!response.header.is_response()) {
        return std::unexpected(ResponseMismatch::NotResponse);
    }
    if (response.header.id != transaction_id) {
        return std::unexpected(ResponseMismatch::TransactionId);
    }
    if (response.header.opcode() != 0) {
        return std::unexpected(ResponseMismatch::Opcode);
    }
    if (response.questions.size() != 1) {
        return std::unexpected(ResponseMismatch::QuestionCount);
    }

    const auto& received_question = response.questions.front();
    if (!dns::names_equal_case_insensitive(received_question.name, question.name)) {
        return std::unexpected(ResponseMismatch::QuestionName);
    }
    if (received_question.type != question.type) {
        return std::unexpected(ResponseMismatch::QuestionType);
    }
    if (received_question.qclass != question.qclass) {
        return std::unexpected(ResponseMismatch::QuestionClass);
    }
    return {};
}

} // namespace dnslab::app
