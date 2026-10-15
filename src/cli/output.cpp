#include "cli/output.hpp"

#include "dns/name_codec.hpp"
#include "net/endpoint.hpp"

#include <algorithm>
#include <iomanip>
#include <ostream>
#include <span>
#include <sstream>
#include <string>
#include <type_traits>
#include <variant>

namespace dnslab::cli {
namespace {

std::string_view transport_name(app::QueryTransport transport) {
    switch (transport) {
    case app::QueryTransport::Udp: return "udp";
    case app::QueryTransport::Tcp: return "tcp";
    case app::QueryTransport::Doh: return "doh";
    case app::QueryTransport::Dot: return "dot";
    }
    return "unknown";
}

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
    default: return "TYPE" + std::to_string(type);
    }
}

std::string class_name(std::uint16_t rr_class) {
    switch (rr_class) {
    case 1: return "IN";
    case 3: return "CH";
    case 4: return "HS";
    default: return "CLASS" + std::to_string(rr_class);
    }
}

std::string rcode_text(std::uint8_t rcode) {
    std::string name;
    switch (rcode) {
    case 0: name = "NOERROR"; break;
    case 1: name = "FORMERR"; break;
    case 2: name = "SERVFAIL"; break;
    case 3: name = "NXDOMAIN"; break;
    case 4: name = "NOTIMP"; break;
    case 5: name = "REFUSED"; break;
    default: name = "RCODE" + std::to_string(rcode); break;
    }
    return name + " (" + std::to_string(rcode) + ")";
}

std::string milliseconds(std::chrono::microseconds elapsed) {
    std::ostringstream text;
    text << std::fixed << std::setprecision(3)
         << std::chrono::duration<double, std::milli>{elapsed}.count();
    return text.str();
}

std::string_view error_name(app::QueryErrorCode code) {
    switch (code) {
    case app::QueryErrorCode::InvalidMode: return "InvalidMode";
    case app::QueryErrorCode::InvalidTimeout: return "InvalidTimeout";
    case app::QueryErrorCode::InvalidEndpoint: return "InvalidEndpoint";
    case app::QueryErrorCode::Encode: return "Encode";
    case app::QueryErrorCode::IdGeneration: return "IdGeneration";
    case app::QueryErrorCode::Network: return "Network";
    case app::QueryErrorCode::Timeout: return "Timeout";
    case app::QueryErrorCode::InvalidResponse: return "InvalidResponse";
    }
    return "Unknown";
}

std::string_view encrypted_error_name(net::EncryptedErrorCode code) {
    switch (code) {
    case net::EncryptedErrorCode::InvalidEndpoint: return "InvalidEndpoint";
    case net::EncryptedErrorCode::InvalidTlsOptions: return "InvalidTlsOptions";
    case net::EncryptedErrorCode::InvalidMessageLength: return "InvalidMessageLength";
    case net::EncryptedErrorCode::BackendUnavailable: return "BackendUnavailable";
    case net::EncryptedErrorCode::Backend: return "Backend";
    case net::EncryptedErrorCode::CertificateVerification: return "CertificateVerification";
    case net::EncryptedErrorCode::TimedOut: return "TimedOut";
    case net::EncryptedErrorCode::HttpStatus: return "HttpStatus";
    case net::EncryptedErrorCode::InvalidContentType: return "InvalidContentType";
    case net::EncryptedErrorCode::ConnectionClosed: return "ConnectionClosed";
    }
    return "Unknown";
}

std::string_view operation_name(net::NetworkOperation operation) {
    switch (operation) {
    case net::NetworkOperation::Startup: return "Startup";
    case net::NetworkOperation::SocketCreate: return "SocketCreate";
    case net::NetworkOperation::SetNonBlocking: return "SetNonBlocking";
    case net::NetworkOperation::Bind: return "Bind";
    case net::NetworkOperation::LocalEndpoint: return "LocalEndpoint";
    case net::NetworkOperation::WaitRead: return "WaitRead";
    case net::NetworkOperation::WaitWrite: return "WaitWrite";
    case net::NetworkOperation::Send: return "Send";
    case net::NetworkOperation::Receive: return "Receive";
    case net::NetworkOperation::Connect: return "Connect";
    }
    return "Unknown";
}

std::string_view network_error_name(net::NetworkErrorCode code) {
    switch (code) {
    case net::NetworkErrorCode::System: return "System";
    case net::NetworkErrorCode::TimedOut: return "TimedOut";
    case net::NetworkErrorCode::InvalidArgument: return "InvalidArgument";
    case net::NetworkErrorCode::DatagramTruncated: return "DatagramTruncated";
    case net::NetworkErrorCode::IncompleteDatagram: return "IncompleteDatagram";
    case net::NetworkErrorCode::ConnectionClosed: return "ConnectionClosed";
    case net::NetworkErrorCode::InvalidMessageLength: return "InvalidMessageLength";
    }
    return "Unknown";
}

std::string_view mismatch_name(app::ResponseMismatch mismatch) {
    switch (mismatch) {
    case app::ResponseMismatch::NotResponse: return "NotResponse";
    case app::ResponseMismatch::TransactionId: return "TransactionId";
    case app::ResponseMismatch::Opcode: return "Opcode";
    case app::ResponseMismatch::QuestionCount: return "QuestionCount";
    case app::ResponseMismatch::QuestionName: return "QuestionName";
    case app::ResponseMismatch::QuestionType: return "QuestionType";
    case app::ResponseMismatch::QuestionClass: return "QuestionClass";
    }
    return "Unknown";
}

void print_failure(std::ostream& output, app::QueryErrorCode code,
                   const app::QueryErrorDetail& detail) {
    output << error_name(code);
    std::visit([&](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, net::EncryptedError>) {
            output << ": " << encrypted_error_name(value.code);
            if (value.backend_code != 0) { output << " (backend " << value.backend_code << ')'; }
            if (value.http_status != 0) { output << " (HTTP " << value.http_status << ')'; }
        } else if constexpr (std::is_same_v<T, net::NetworkError>) {
            output << ": " << operation_name(value.operation) << '/' << network_error_name(value.code)
                   << " (system " << value.system_code << ')';
        } else if constexpr (std::is_same_v<T, dns::DnsParseError>) {
            output << ": DNS parse error " << static_cast<int>(value.code)
                   << " at byte " << value.offset;
        } else if constexpr (std::is_same_v<T, dns::DnsEncodeError>) {
            output << ": DNS encode error " << static_cast<int>(value.code)
                   << " at label " << value.label_index;
        } else if constexpr (std::is_same_v<T, app::ResponseMismatch>) {
            output << ": " << mismatch_name(value);
        }
    }, detail);
}

void print_question(std::ostream& output, const dns::DnsQuestion& question) {
    output << "Question: " << dns::format_name(question.name) << ' '
           << class_name(question.qclass) << ' ' << type_name(question.type) << '\n';
}

void print_rdata(std::ostream& output, const dns::RData& rdata) {
    std::visit([&](const auto& data) {
        using T = std::decay_t<decltype(data)>;
        if constexpr (std::is_same_v<T, dns::AData>) {
            for (std::size_t index = 0; index < data.address.size(); ++index) {
                if (index != 0) { output << '.'; }
                output << std::to_integer<unsigned int>(data.address[index]);
            }
        } else if constexpr (std::is_same_v<T, dns::AaaaData>) {
            const auto endpoint = net::format_endpoint(net::Endpoint{data.address, 0});
            output << endpoint.substr(1, endpoint.find(']') - 1);
        } else if constexpr (std::is_same_v<T, dns::NameData>) {
            output << dns::format_name(data.name);
        } else if constexpr (std::is_same_v<T, dns::OpaqueData>) {
            constexpr std::string_view hex{"0123456789abcdef"};
            output << "\\# " << data.bytes.size();
            if (!data.bytes.empty()) { output << ' '; }
            for (const auto byte : data.bytes) {
                const auto value = std::to_integer<unsigned int>(byte);
                output << hex[value >> 4U] << hex[value & 0xfU];
            }
        }
    }, rdata);
}

void print_section(std::ostream& output, std::string_view name,
                   std::span<const dns::ResourceRecord> records) {
    output << name << ": " << records.size() << '\n';
    for (const auto& record : records) {
        output << "  " << dns::format_name(record.owner) << ' ' << record.ttl << ' '
               << class_name(record.rr_class) << ' ' << type_name(record.type) << ' ';
        print_rdata(output, record.rdata);
        output << '\n';
    }
}

void print_attempts(std::ostream& output, std::span<const app::QueryAttempt> attempts) {
    output << "Attempts: " << attempts.size() << '\n';
    for (std::size_t index = 0; index < attempts.size(); ++index) {
        const auto& attempt = attempts[index];
        output << "  " << index + 1 << ". " << transport_name(attempt.transport) << ' '
               << milliseconds(attempt.elapsed) << " ms: ";
        if (attempt.outcome) {
            output << "RCODE " << rcode_text(attempt.outcome->header.rcode())
                   << ", TC=" << (attempt.outcome->header.truncated() ? '1' : '0');
        } else {
            print_failure(output, attempt.outcome.error().code, attempt.outcome.error().detail);
        }
        output << ", ignored=" << attempt.ignored_messages << '\n';
    }
}

template <typename Result>
void print_success(std::ostream& output, std::string_view target, const Result& result) {
    output << "Target: " << target << '\n'
           << "Transport: " << transport_name(result.transport) << '\n'
           << "Elapsed: " << milliseconds(result.elapsed) << " ms\n"
           << "RCODE: " << rcode_text(result.response.header.rcode()) << '\n'
           << "Transaction ID: " << result.transaction_id << '\n'
           << "TC: " << (result.response.header.truncated() ? '1' : '0') << '\n';
    print_question(output, result.question);
    print_section(output, "Answer", result.response.answers);
    const bool direct_answer = std::any_of(result.response.answers.begin(), result.response.answers.end(),
        [&](const dns::ResourceRecord& record) {
            return record.type == result.question.type && record.rr_class == result.question.qclass &&
                   dns::names_equal_case_insensitive(record.owner, result.question.name);
        });
    if (result.response.header.rcode() == 0 && !direct_answer) {
        output << "Note: NOERROR response has no direct " << type_name(result.question.type)
               << " answer for " << dns::format_name(result.question.name) << '\n';
    }
    print_section(output, "Authority", result.response.authority);
    print_section(output, "Additional", result.response.additional);
    print_attempts(output, result.attempts);
}

} // namespace

void print_result(std::ostream& output, const app::QueryResult& result) {
    print_success(output, net::format_endpoint(result.server), result);
}

void print_result(std::ostream& output, const app::EncryptedQueryResult& result) {
    print_success(output, result.server.address, result);
}

void print_error(std::ostream& output, std::ostream& errors,
                 std::string_view target, std::string_view requested_transport,
                 const dns::DnsQuestion& question, const app::QueryError& error) {
    output << "Target: " << target << '\n' << "Transport: ";
    if (error.attempts.empty()) {
        output << requested_transport;
    } else {
        output << transport_name(error.attempts.back().transport);
    }
    output << '\n' << "Elapsed: " << milliseconds(error.elapsed) << " ms\n";
    print_question(output, question);
    print_attempts(output, error.attempts);
    errors << "Query failed: ";
    print_failure(errors, error.code, error.detail);
    errors << '\n';
}

} // namespace dnslab::cli
