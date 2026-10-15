#include "app/response_validator.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace {

using namespace dnslab::app;
using namespace dnslab::dns;

constexpr std::uint16_t transaction_id = 0x1234;

static_assert(noexcept(validate_response(std::declval<const DnsMessage&>(),
                                        std::declval<const DnsQuestion&>(),
                                        std::uint16_t{})));

/// 构造用于响应匹配的 example.com IN A 问题。
DnsQuestion example_question() {
    return {DnsName{{"example", "com"}}, 1, 1};
}

/// 为给定问题和事务 ID 构造最小响应。
DnsMessage response_for(const DnsQuestion& question, std::uint16_t id = transaction_id) {
    DnsMessage response;
    response.header = DnsHeader{id, 0x8000};
    response.questions.push_back(question);
    return response;
}

/// 断言响应校验失败并返回预期的不匹配原因。
void check_mismatch(const DnsMessage& response, const DnsQuestion& question,
                    std::uint16_t id, ResponseMismatch mismatch) {
    const auto result = validate_response(response, question, id);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == mismatch);
}

TEST_CASE("匹配的响应可以没有应答记录", "[response_validator]") {
    const auto question = example_question();
    const auto response = response_for(question);

    CHECK(validate_response(response, question, transaction_id).has_value());
}

TEST_CASE("响应匹配拒绝未设置响应标志的报文",
          "[response_validator][mismatch]") {
    const auto question = example_question();
    auto response = response_for(question);
    response.header.flags = 0x0180;

    check_mismatch(response, question, transaction_id, ResponseMismatch::NotResponse);
}

TEST_CASE("响应事务 ID 精确匹配并覆盖零和最大值",
          "[response_validator][mismatch]") {
    const auto question = example_question();
    for (const auto id : std::array<std::uint16_t, 4>{0, 1, 0x1234, 0xffff}) {
        CAPTURE(id);
        const auto response = response_for(question, id);
        CHECK(validate_response(response, question, id).has_value());
        const auto other_id = static_cast<std::uint16_t>(id ^ 0xffffU);
        check_mismatch(response, question, other_id, ResponseMismatch::TransactionId);
    }
}

TEST_CASE("响应匹配拒绝所有非标准操作码",
          "[response_validator][mismatch]") {
    const auto question = example_question();
    auto response = response_for(question);
    for (unsigned int opcode = 1; opcode < 16; ++opcode) {
        CAPTURE(opcode);
        response.header.flags = static_cast<std::uint16_t>(0x8000U | (opcode << 11));
        check_mismatch(response, question, transaction_id, ResponseMismatch::Opcode);
    }
}

TEST_CASE("响应必须恰好包含一个问题",
          "[response_validator][mismatch]") {
    const auto question = example_question();
    auto response = response_for(question);
    response.questions.clear();
    check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionCount);

    response.questions = {question, question};
    check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionCount);
}

TEST_CASE("响应问题的名称必须与请求域名一致",
          "[response_validator][mismatch]") {
    const auto question = example_question();
    auto response = response_for(question);
    response.questions.front().name = DnsName{{"different", "com"}};

    check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionName);
}

TEST_CASE("响应问题类型保留完整十六位",
          "[response_validator][mismatch]") {
    auto question = example_question();
    for (const auto type : std::array<std::uint16_t, 6>{0, 1, 28, 0x00ff, 0xff00, 0xffff}) {
        CAPTURE(type);
        question.type = type;
        auto response = response_for(question);
        CHECK(validate_response(response, question, transaction_id).has_value());

        response.questions.front().type = static_cast<std::uint16_t>(type ^ 0x0100U);
        check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionType);
    }
}

TEST_CASE("响应问题类别保留完整十六位",
          "[response_validator][mismatch]") {
    auto question = example_question();
    for (const auto qclass : std::array<std::uint16_t, 6>{0, 1, 3, 0x00ff, 0xff00, 0xffff}) {
        CAPTURE(qclass);
        question.qclass = qclass;
        auto response = response_for(question);
        CHECK(validate_response(response, question, transaction_id).has_value());

        response.questions.front().qclass = static_cast<std::uint16_t>(qclass ^ 0x0100U);
        check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionClass);
    }
}

TEST_CASE("响应不匹配错误遵守约定的优先级",
          "[response_validator][mismatch]") {
    const auto question = example_question();
    auto response = response_for(question);
    response.header = DnsHeader{0xabcd, 0x0800};
    response.questions = {
        DnsQuestion{DnsName{{"other", "com"}}, 28, 3},
        question,
    };

    check_mismatch(response, question, transaction_id, ResponseMismatch::NotResponse);
    response.header.flags = 0x8800;
    check_mismatch(response, question, transaction_id, ResponseMismatch::TransactionId);
    response.header.id = transaction_id;
    check_mismatch(response, question, transaction_id, ResponseMismatch::Opcode);
    response.header.flags = 0x8000;
    check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionCount);
    response.questions.resize(1);
    check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionName);
    response.questions.front().name = question.name;
    check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionType);
    response.questions.front().type = question.type;
    check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionClass);
    response.questions.front().qclass = question.qclass;
    CHECK(validate_response(response, question, transaction_id).has_value());
}

TEST_CASE("响应名称比较忽略 ASCII 字母大小写", "[response_validator][name]") {
    const auto question = example_question();
    auto response = response_for(question);
    response.questions.front().name = DnsName{{"ExAmPlE", "COM"}};

    CHECK(validate_response(response, question, transaction_id).has_value());
}

TEST_CASE("根名问题只与根名问题匹配", "[response_validator][name]") {
    const DnsQuestion root{DnsName{}, 28, 1};
    auto response = response_for(root);
    CHECK(validate_response(response, root, transaction_id).has_value());

    const auto ordinary = example_question();
    check_mismatch(response, ordinary, transaction_id, ResponseMismatch::QuestionName);
    response.questions.front() = ordinary;
    check_mismatch(response, root, transaction_id, ResponseMismatch::QuestionName);
}

TEST_CASE("响应名称匹配保留标签边界", "[response_validator][name]") {
    struct Names {
        DnsName requested;
        DnsName received;
    };
    const std::array samples{
        Names{DnsName{{"ab", "c"}}, DnsName{{"a", "bc"}}},
        Names{DnsName{{"a.b", "c"}}, DnsName{{"a", "b.c"}}},
        Names{DnsName{{"a", "b"}}, DnsName{{"a.b"}}},
    };
    for (const auto& sample : samples) {
        const DnsQuestion question{sample.requested, 1, 1};
        auto response = response_for(question);
        response.questions.front().name = sample.received;
        check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionName);
    }
}

TEST_CASE("响应匹配保留原始标签字节且仅折叠 ASCII 大小写",
          "[response_validator][name]") {
    const std::string label{
        'A', '\0', static_cast<char>(0x1b), '.', '\\',
        static_cast<char>(0x80), static_cast<char>(0xc0), static_cast<char>(0xff)};
    const DnsQuestion question{DnsName{{label, "EXAMPLE"}}, 1, 1};
    auto response = response_for(question);
    response.questions.front().name.labels.front()[0] = 'a';
    response.questions.front().name.labels[1] = "example";
    CHECK(validate_response(response, question, transaction_id).has_value());

    response.questions.front().name.labels.front()[6] = static_cast<char>(0xe0);
    check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionName);

    response.questions.front().name.labels.front()[6] = static_cast<char>(0xc0);
    response.questions.front().name.labels.front()[1] = 'x';
    check_mismatch(response, question, transaction_id, ResponseMismatch::QuestionName);
}

TEST_CASE("响应码截断标志及操作码之外的标志不妨碍匹配",
          "[response_validator][flags]") {
    const auto question = example_question();
    auto response = response_for(question);
    constexpr std::array<std::uint16_t, 9> flags{
        0x8000, 0x8400, 0x8200, 0x8100, 0x8080, 0x8040, 0x8020, 0x8010, 0x87f0,
    };
    for (const auto pattern : flags) {
        for (unsigned int rcode = 0; rcode < 16; ++rcode) {
            CAPTURE(pattern, rcode);
            response.header.flags = static_cast<std::uint16_t>(pattern | rcode);
            CHECK(validate_response(response, question, transaction_id).has_value());
        }
    }
}

TEST_CASE("响应匹配不解释资源记录区段",
          "[response_validator]") {
    const auto question = example_question();
    auto response = response_for(question);
    const ResourceRecord opaque{
        DnsName{{"other", "example"}}, 65000, 3, 123,
        OpaqueData{Packet{std::byte{0xff}, std::byte{0x00}}},
    };
    response.answers.push_back(opaque);
    response.authority.push_back(opaque);
    response.additional.push_back(opaque);

    CHECK(validate_response(response, question, transaction_id).has_value());
}

} // 命名空间
