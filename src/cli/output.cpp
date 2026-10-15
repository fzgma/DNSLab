#include "cli/output.hpp"

#include "dns/name_codec.hpp"
#include "net/endpoint.hpp"

#include <algorithm>
#include <format>
#include <print>
#include <span>
#include <string>
#include <type_traits>
#include <variant>

namespace dnslab::cli {
namespace {

/// 返回实际传输方式的协议标识。
std::string_view transport_name(app::QueryTransport transport) {
    switch (transport) {
    case app::QueryTransport::Udp: return "udp";
    case app::QueryTransport::Tcp: return "tcp";
    case app::QueryTransport::Doh: return "doh";
    case app::QueryTransport::Dot: return "dot";
    }
    return "未知";
}

/// 将记录类型转为标准名称，并保留未知类型的数字编号。
std::string type_name(std::uint16_t type) {
    switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 41: return "OPT";
    default: return std::format("TYPE{}", type);
    }
}

/// 将记录类别转为标准名称，并保留未知类别的数字编号。
std::string class_name(std::uint16_t rr_class) {
    switch (rr_class) {
    case 1: return "IN";
    case 3: return "CH";
    case 4: return "HS";
    default: return std::format("CLASS{}", rr_class);
    }
}

/// 同时展示 DNS 响应码的标准名称和原始数值。
std::string rcode_text(std::uint8_t rcode) {
    std::string name;
    switch (rcode) {
    case 0: name = "NOERROR"; break;
    case 1: name = "FORMERR"; break;
    case 2: name = "SERVFAIL"; break;
    case 3: name = "NXDOMAIN"; break;
    case 4: name = "NOTIMP"; break;
    case 5: name = "REFUSED"; break;
    default: name = std::format("RCODE{}", rcode); break;
    }
    return std::format("{} ({})", name, rcode);
}

/// 将微秒耗时转换为保留三位小数的毫秒数。
std::string milliseconds(std::chrono::microseconds elapsed) {
    return std::format("{:.3f}", std::chrono::duration<double, std::milli>{elapsed}.count());
}

/// 返回查询失败类别的中文说明。
std::string_view error_name(app::QueryErrorCode code) {
    switch (code) {
    case app::QueryErrorCode::InvalidMode: return "传输模式无效";
    case app::QueryErrorCode::InvalidTimeout: return "超时预算无效";
    case app::QueryErrorCode::InvalidEndpoint: return "服务器地址无效";
    case app::QueryErrorCode::Encode: return "查询编码失败";
    case app::QueryErrorCode::IdGeneration: return "事务 ID 生成失败";
    case app::QueryErrorCode::Network: return "网络失败";
    case app::QueryErrorCode::Timeout: return "查询超时";
    case app::QueryErrorCode::InvalidResponse: return "响应无效";
    }
    return "未知错误";
}

/// 返回加密传输失败原因的中文说明。
std::string_view encrypted_error_name(net::EncryptedErrorCode code) {
    switch (code) {
    case net::EncryptedErrorCode::InvalidEndpoint: return "服务器地址无效";
    case net::EncryptedErrorCode::InvalidTlsOptions: return "TLS 配置无效";
    case net::EncryptedErrorCode::InvalidMessageLength: return "消息长度无效";
    case net::EncryptedErrorCode::BackendUnavailable: return "加密后端能力不足";
    case net::EncryptedErrorCode::Backend: return "加密后端失败";
    case net::EncryptedErrorCode::CertificateVerification: return "证书验证失败";
    case net::EncryptedErrorCode::TimedOut: return "查询超时";
    case net::EncryptedErrorCode::HttpStatus: return "HTTP 状态异常";
    case net::EncryptedErrorCode::InvalidContentType: return "响应媒体类型无效";
    case net::EncryptedErrorCode::ConnectionClosed: return "连接提前关闭";
    }
    return "未知错误";
}

/// 返回系统网络操作所处阶段的中文说明。
std::string_view operation_name(net::NetworkOperation operation) {
    switch (operation) {
    case net::NetworkOperation::Startup: return "初始化网络";
    case net::NetworkOperation::SocketCreate: return "创建套接字";
    case net::NetworkOperation::SetNonBlocking: return "设置非阻塞";
    case net::NetworkOperation::Bind: return "绑定地址";
    case net::NetworkOperation::LocalEndpoint: return "读取本地地址";
    case net::NetworkOperation::WaitRead: return "等待可读";
    case net::NetworkOperation::WaitWrite: return "等待可写";
    case net::NetworkOperation::Send: return "发送数据";
    case net::NetworkOperation::Receive: return "接收数据";
    case net::NetworkOperation::Connect: return "建立连接";
    }
    return "未知阶段";
}

/// 返回系统网络错误类别的中文说明。
std::string_view network_error_name(net::NetworkErrorCode code) {
    switch (code) {
    case net::NetworkErrorCode::System: return "系统错误";
    case net::NetworkErrorCode::TimedOut: return "等待超时";
    case net::NetworkErrorCode::InvalidArgument: return "网络参数无效";
    case net::NetworkErrorCode::DatagramTruncated: return "数据报被截断";
    case net::NetworkErrorCode::IncompleteDatagram: return "数据报发送不完整";
    case net::NetworkErrorCode::ConnectionClosed: return "连接提前关闭";
    case net::NetworkErrorCode::InvalidMessageLength: return "消息长度无效";
    }
    return "未知错误";
}

/// 返回 DNS 响应与请求不匹配的具体原因。
std::string_view mismatch_name(app::ResponseMismatch mismatch) {
    switch (mismatch) {
    case app::ResponseMismatch::NotResponse: return "收到的报文不是响应";
    case app::ResponseMismatch::TransactionId: return "事务 ID 不匹配";
    case app::ResponseMismatch::Opcode: return "操作码不匹配";
    case app::ResponseMismatch::QuestionCount: return "问题数量不匹配";
    case app::ResponseMismatch::QuestionName: return "查询名称不匹配";
    case app::ResponseMismatch::QuestionType: return "查询类型不匹配";
    case app::ResponseMismatch::QuestionClass: return "查询类别不匹配";
    }
    return "未知匹配错误";
}

/// 返回 DNS 报文解析错误的中文说明。
std::string_view parse_error_name(dns::DnsParseErrorCode code) {
    switch (code) {
    case dns::DnsParseErrorCode::FieldOutOfBounds: return "字段越过报文边界";
    case dns::DnsParseErrorCode::NameOutOfBounds: return "名称越过报文边界";
    case dns::DnsParseErrorCode::ReservedLabelEncoding: return "名称使用保留的标签编码";
    case dns::DnsParseErrorCode::CompressionPointerTruncated: return "压缩指针不完整";
    case dns::DnsParseErrorCode::CompressionPointerOutOfBounds: return "压缩指针越界";
    case dns::DnsParseErrorCode::CompressionPointerNotBackward: return "压缩指针未指向更早的字节";
    case dns::DnsParseErrorCode::CompressionLoop: return "名称压缩出现循环";
    case dns::DnsParseErrorCode::ExpandedNameTooLong: return "展开后的名称过长";
    case dns::DnsParseErrorCode::PacketTooShort: return "报文过短";
    case dns::DnsParseErrorCode::PacketTooLarge: return "报文过长";
    case dns::DnsParseErrorCode::SectionCountMismatch: return "记录数量与报文不符";
    case dns::DnsParseErrorCode::InvalidRdataLength: return "记录数据长度无效";
    case dns::DnsParseErrorCode::RdataLengthMismatch: return "记录数据与声明长度不符";
    case dns::DnsParseErrorCode::TrailingData: return "报文末尾存在多余数据";
    }
    return "未知解析错误";
}

/// 返回 DNS 查询编码错误的中文说明。
std::string_view encode_error_name(dns::DnsEncodeErrorCode code) {
    switch (code) {
    case dns::DnsEncodeErrorCode::EmptyLabel: return "名称包含空标签";
    case dns::DnsEncodeErrorCode::LabelTooLong: return "名称标签过长";
    case dns::DnsEncodeErrorCode::NameTooLong: return "完整名称过长";
    case dns::DnsEncodeErrorCode::UnsupportedQueryType: return "不支持该查询类型";
    case dns::DnsEncodeErrorCode::UnsupportedQueryClass: return "不支持该查询类别";
    }
    return "未知编码错误";
}

/// 展示查询错误的中文类别、具体原因和原始数字诊断信息。
void print_failure(std::FILE* output, app::QueryErrorCode code,
                   const app::QueryErrorDetail& detail) {
    std::print(output, "{}", error_name(code));
    /// 按错误详情的实际类型保留阶段、偏移及底层数字错误码。
    std::visit([&](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, net::EncryptedError>) {
            std::print(output, ": {}", encrypted_error_name(value.code));
            if (value.backend_code != 0) { std::print(output, "（后端错误码 {}）", value.backend_code); }
            if (value.http_status != 0) { std::print(output, "（HTTP 状态 {}）", value.http_status); }
        } else if constexpr (std::is_same_v<T, net::NetworkError>) {
            std::print(output, ": {}/{}（系统错误码 {}）", operation_name(value.operation),
                       network_error_name(value.code), value.system_code);
        } else if constexpr (std::is_same_v<T, dns::DnsParseError>) {
            std::print(output, ": DNS 报文解析失败: {}（错误码 {}，字节偏移 {}）",
                       parse_error_name(value.code), static_cast<int>(value.code), value.offset);
        } else if constexpr (std::is_same_v<T, dns::DnsEncodeError>) {
            std::print(output, ": DNS 查询编码失败: {}（错误码 {}，标签索引 {}）",
                       encode_error_name(value.code), static_cast<int>(value.code), value.label_index);
        } else if constexpr (std::is_same_v<T, app::ResponseMismatch>) {
            std::print(output, ": {}", mismatch_name(value));
        }
    }, detail);
}

/// 展示查询名称、类别与记录类型。
void print_question(std::FILE* output, const dns::DnsQuestion& question) {
    std::println(output, "问题: {} {} {}", dns::format_name(question.name),
                 class_name(question.qclass), type_name(question.type));
}

/// 展示已解析的记录值，并将未知记录保留为长度和十六进制字节。
void print_rdata(std::FILE* output, const dns::RData& rdata) {
    /// 按记录数据的实际类型选择地址、名称或原始字节格式。
    std::visit([&](const auto& data) {
        using T = std::decay_t<decltype(data)>;
        if constexpr (std::is_same_v<T, dns::AData>) {
            for (std::size_t index = 0; index < data.address.size(); ++index) {
                std::print(output, "{}{}", index == 0 ? "" : ".",
                           std::to_integer<unsigned int>(data.address[index]));
            }
        } else if constexpr (std::is_same_v<T, dns::AaaaData>) {
            const auto endpoint = net::format_endpoint(net::Endpoint{data.address, 0});
            std::print(output, "{}", endpoint.substr(1, endpoint.find(']') - 1));
        } else if constexpr (std::is_same_v<T, dns::NameData>) {
            std::print(output, "{}", dns::format_name(data.name));
        } else if constexpr (std::is_same_v<T, dns::OpaqueData>) {
            std::print(output, "\\# {}", data.bytes.size());
            if (!data.bytes.empty()) { std::print(output, " "); }
            for (const auto byte : data.bytes) {
                std::print(output, "{:02x}", std::to_integer<unsigned int>(byte));
            }
        }
    }, rdata);
}

/// 展示一个记录分区的数量及全部记录，保留记录所在分区。
void print_section(std::FILE* output, std::string_view name,
                   std::span<const dns::ResourceRecord> records) {
    std::println(output, "{}: {}", name, records.size());
    for (const auto& record : records) {
        std::print(output, "  {} {} {} {} ", dns::format_name(record.owner), record.ttl,
                   class_name(record.rr_class), type_name(record.type));
        print_rdata(output, record.rdata);
        std::println(output, "");
    }
}

/// 按发生顺序展示各次传输的耗时、响应或失败及忽略消息数量。
void print_attempts(std::FILE* output, std::span<const app::QueryAttempt> attempts) {
    std::println(output, "尝试: {}", attempts.size());
    for (std::size_t index = 0; index < attempts.size(); ++index) {
        const auto& attempt = attempts[index];
        std::print(output, "  {}. {} {} 毫秒: ", index + 1, transport_name(attempt.transport),
                   milliseconds(attempt.elapsed));
        if (attempt.outcome) {
            std::print(output, "RCODE {}, TC={}", rcode_text(attempt.outcome->header.rcode()),
                       attempt.outcome->header.truncated() ? 1 : 0);
        } else {
            print_failure(output, attempt.outcome.error().code, attempt.outcome.error().detail);
        }
        std::println(output, ", 已忽略={}", attempt.ignored_messages);
    }
}

/// 展示成功查询的上下文、完整响应与尝试记录。
template <typename Result>
void print_success(std::FILE* output, std::string_view target, const Result& result) {
    std::println(output, "目标: {}\n传输: {}\n耗时: {} 毫秒\n响应码: {}\n事务 ID: {}\n截断 TC: {}",
                 target, transport_name(result.transport), milliseconds(result.elapsed),
                 rcode_text(result.response.header.rcode()), result.transaction_id,
                 result.response.header.truncated() ? 1 : 0);
    print_question(output, result.question);
    print_section(output, "回答", result.response.answers);
    /// 直接答案必须匹配原查询名称、类型和类别，CNAME 目标上的地址不算直接答案。
    const bool direct_answer = std::any_of(result.response.answers.begin(), result.response.answers.end(),
        [&](const dns::ResourceRecord& record) {
            return record.type == result.question.type && record.rr_class == result.question.qclass &&
                   dns::names_equal_case_insensitive(record.owner, result.question.name);
        });
    if (result.response.header.rcode() == 0 && !direct_answer) {
        std::println(output, "提示: NOERROR 响应没有 {} 的直接 {} 回答。",
                     dns::format_name(result.question.name), type_name(result.question.type));
    }
    print_section(output, "权威记录", result.response.authority);
    print_section(output, "附加记录", result.response.additional);
    print_attempts(output, result.attempts);
}

} // 匿名命名空间

/// 展示普通查询的规范服务器地址及查询结果。
void print_result(std::FILE* output, const app::QueryResult& result) {
    print_success(output, net::format_endpoint(result.server), result);
}

/// 展示加密查询的规范服务器地址及查询结果。
void print_result(std::FILE* output, const app::EncryptedQueryResult& result) {
    print_success(output, result.server.address, result);
}

/// 保留失败查询的目标与尝试过程，并单独输出最终中文错误。
void print_error(std::FILE* output, std::FILE* errors,
                 std::string_view target, std::string_view requested_transport,
                 const dns::DnsQuestion& question, const app::QueryError& error) {
    const auto transport = error.attempts.empty()
        ? requested_transport : transport_name(error.attempts.back().transport);
    std::println(output, "目标: {}\n传输: {}\n耗时: {} 毫秒",
                 target, transport, milliseconds(error.elapsed));
    print_question(output, question);
    print_attempts(output, error.attempts);
    std::print(errors, "查询失败: ");
    print_failure(errors, error.code, error.detail);
    std::println(errors, "");
}

} // 命名空间 dnslab::cli
