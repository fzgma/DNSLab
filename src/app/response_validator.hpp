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

/// 按错误枚举顺序核对已解析响应是否匹配标准查询。
// 来源端点和报文结构由其他层校验，此处只检查事务与问题信息。
[[nodiscard]] std::expected<void, ResponseMismatch>
validate_response(const dns::DnsMessage& response, const dns::DnsQuestion& question,
                  std::uint16_t transaction_id) noexcept;

} // 命名空间 dnslab::app
