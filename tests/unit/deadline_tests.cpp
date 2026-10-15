#include "net/deadline.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>

namespace {

using namespace dnslab::net;
using namespace std::chrono_literals;
using Milliseconds = std::chrono::milliseconds;
using ClockDuration = Deadline::Clock::duration;
using TimePoint = Deadline::TimePoint;

/// 验证超时输入的错误类别和原始字节偏移。
void check_input_error(std::string_view input, TimeoutInputErrorCode code,
                       std::size_t offset) {
    const auto result = parse_timeout_ms(input);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().offset == offset);
}

TEST_CASE("超时输入接受上下限和前导零",
          "[deadline][input]") {
    struct Sample {
        std::string input;
        Milliseconds expected;
    };
    const std::array samples{
        Sample{"100", 100ms}, Sample{"1500", 1500ms}, Sample{"30000", 30000ms},
        Sample{"000100", 100ms}, Sample{"00030000", 30000ms},
        Sample{std::string(500, '0') + "100", 100ms},
    };

    for (const auto& sample : samples) {
        CAPTURE(sample.input);
        const auto result = parse_timeout_ms(sample.input);
        REQUIRE(result.has_value());
        CHECK(*result == sample.expected);
    }
}

TEST_CASE("超时输入拒绝空值及越界数值且不发生溢出",
          "[deadline][input]") {
    check_input_error("", TimeoutInputErrorCode::EmptyValue, 0);
    for (const auto input : {"0", "0000", "99", "30001", "99999999999999999999"}) {
        CAPTURE(input);
        check_input_error(input, TimeoutInputErrorCode::OutOfRange, 0);
    }
    check_input_error(std::string(1000, '9'), TimeoutInputErrorCode::OutOfRange, 0);
}

TEST_CASE("超时输入先检查所有字节再报告范围错误",
          "[deadline][input]") {
    struct Sample {
        std::string input;
        std::size_t offset;
    };
    const std::array samples{
        Sample{" 100", 0}, Sample{"100 ", 3}, Sample{"+100", 0},
        Sample{"-100", 0}, Sample{"100.0", 3}, Sample{"1e3", 1},
        Sample{"\t100", 0}, Sample{"100\n", 3},
        Sample{std::string{"10\0" "0", 4}, 2},
        Sample{"\xEF\xBC\x91" "00", 0},
        Sample{std::string(1000, '9') + "x", 1000},
    };

    for (const auto& sample : samples) {
        CAPTURE(sample.input, sample.offset);
        check_input_error(sample.input, TimeoutInputErrorCode::InvalidCharacter,
                          sample.offset);
    }
}

TEST_CASE("截止时间保存绝对时刻且不会因读取而变化",
          "[deadline]") {
    const auto now = TimePoint{} + 10s;
    const auto expiration = now + 1500ms;
    const Deadline deadline{expiration};

    CHECK(deadline.expires_at() == expiration);
    CHECK_FALSE(deadline.expired(now));
    CHECK(deadline.remaining(now) == 1500ms);
    CHECK(deadline.remaining(now + 400ms) == 1100ms);
    CHECK(deadline.remaining(now) == 1500ms);
    CHECK(deadline.expires_at() == expiration);
}

TEST_CASE("截止时间计算在跨越时钟纪元时保留普通预算",
          "[deadline]") {
    for (const auto started_at : {TimePoint{} - 1s, TimePoint{}, TimePoint{} + 1s}) {
        for (const auto budget : {100ms, 1500ms, 30000ms}) {
            CAPTURE(budget.count());
            const auto deadline = Deadline::after(budget, started_at);
            CHECK(deadline.expires_at() == started_at + budget);
            CHECK(deadline.remaining(started_at) == budget);
        }
    }
}

TEST_CASE("截止时间在边界处到期且之后剩余时间保持为零",
          "[deadline]") {
    const auto cutoff = TimePoint{} + 1500ms;
    const Deadline deadline{cutoff};

    CHECK_FALSE(deadline.expired(cutoff - 1ms));
    CHECK(deadline.remaining(cutoff - 1ms) == 1ms);
    CHECK(deadline.expired(cutoff));
    CHECK(deadline.remaining(cutoff) == 0ms);
    CHECK(deadline.expired(cutoff + 1ms));
    CHECK(deadline.remaining(cutoff + 1s) == 0ms);
}

TEST_CASE("正的不足一毫秒余量向上取整",
          "[deadline]") {
    const auto now = TimePoint{};
    const ClockDuration tick{1};

    CHECK(Deadline{now + tick}.remaining(now) == 1ms);
    CHECK(Deadline{now + 1ms}.remaining(now) == 1ms);
    CHECK(Deadline{now + 1ms + tick}.remaining(now) == 2ms);
    const Deadline deadline{now + 1ms};
    CHECK_FALSE(deadline.expired(now + 1ms - tick));
    CHECK(deadline.remaining(now + 1ms - tick) == 1ms);
}

TEST_CASE("UDP 操作和 TCP 回退共用不变的截止时间",
          "[deadline]") {
    const auto started_at = TimePoint{} + 100s;
    const auto deadline = Deadline::after(1500ms, started_at);

    CHECK(deadline.remaining(started_at) == 1500ms);
    CHECK(deadline.remaining(started_at + 400ms) == 1100ms); // UDP 完成。
    CHECK(deadline.remaining(started_at + 900ms) == 600ms); // TCP 连接完成。
    CHECK(deadline.remaining(started_at + 1200ms) == 300ms); // 已接收部分数据。
    CHECK(deadline.remaining(started_at + 1499ms) == 1ms);
    CHECK(deadline.expired(started_at + 1500ms));
    CHECK(deadline.expires_at() == started_at + 1500ms);
}

TEST_CASE("每台服务器拥有独立截止时间",
          "[deadline]") {
    const auto started_at = TimePoint{};
    const auto first = Deadline::after(1500ms, started_at);
    const auto second = Deadline::after(1500ms, started_at + 500ms);

    CHECK(first.remaining(started_at + 500ms) == 1000ms);
    CHECK(second.remaining(started_at + 500ms) == 1500ms);
    CHECK(first.expired(started_at + 1500ms));
    CHECK(second.remaining(started_at + 1500ms) == 500ms);
    CHECK(first.expires_at() == started_at + 1500ms);
    CHECK(second.expires_at() == started_at + 2000ms);
}

TEST_CASE("非正预算立即到期且无需算术换算",
          "[deadline][bounds]") {
    for (const auto started_at : {TimePoint::min(), TimePoint{}, TimePoint::max()}) {
        for (const auto budget : {Milliseconds::min(), -1ms, 0ms}) {
            const auto deadline = Deadline::after(budget, started_at);
            CHECK(deadline.expires_at() == started_at);
            CHECK(deadline.expired(started_at));
            CHECK(deadline.remaining(started_at) == 0ms);
        }
    }
}

TEST_CASE("截止时间创建在最大时间点饱和",
          "[deadline][bounds]") {
    const auto almost_maximum = TimePoint::max() - 1ms;

    CHECK(Deadline::after(1ms, almost_maximum).expires_at() == TimePoint::max());
    CHECK(Deadline::after(2ms, almost_maximum).expires_at() == TimePoint::max());
    CHECK(Deadline::after(100ms, TimePoint::max()).expires_at() == TimePoint::max());
    CHECK(Deadline::after(Milliseconds::max(), TimePoint{}).expires_at() ==
          TimePoint::max());
    CHECK(Deadline::after(Milliseconds::max(), almost_maximum).expires_at() ==
          TimePoint::max());
}

TEST_CASE("截止时间支持接近时钟最小值的时间点",
          "[deadline][bounds]") {
    const auto started_at = TimePoint::min();
    const auto deadline = Deadline::after(1ms, started_at);

    CHECK(deadline.expires_at() == started_at + 1ms);
    CHECK(deadline.remaining(started_at) == 1ms);
    CHECK(deadline.expired(started_at + 1ms));
    CHECK(Deadline{TimePoint::min()}.remaining(TimePoint::max()) == 0ms);
}

TEST_CASE("剩余时间计算覆盖有符号时钟的完整范围",
          "[deadline][bounds]") {
    // 将最大值与最小值之差拆为两个可表示的半段及一个时钟单位，
    // 避免构造期望结果时使有符号时长溢出。
    const auto half = std::chrono::duration_cast<Milliseconds>(ClockDuration::max());
    const auto residual = ClockDuration::max() -
                          std::chrono::duration_cast<ClockDuration>(half);
    const auto tail = std::chrono::ceil<Milliseconds>(residual * 2 + ClockDuration{1});
    const auto expected = half > (Milliseconds::max() - tail) / 2
                              ? Milliseconds::max()
                              : half * 2 + tail;
    const Deadline deadline{TimePoint::max()};

    CHECK(deadline.remaining(TimePoint::min()) == expected);
    CHECK_FALSE(deadline.expired(TimePoint::min()));
    CHECK(deadline.expires_at() == TimePoint::max());
    CHECK(deadline.remaining(TimePoint::max()) == 0ms);
}

TEST_CASE("大预算可跨越时钟纪元且不会提前饱和",
          "[deadline][bounds]") {
    const auto half = std::chrono::duration_cast<Milliseconds>(ClockDuration::max());
    const auto residual = ClockDuration::max() -
                          std::chrono::duration_cast<ClockDuration>(half);
    const auto extra = half < Milliseconds::max() ? 1ms : 0ms;
    const auto expected = TimePoint{
        std::chrono::duration_cast<ClockDuration>(extra) - residual - ClockDuration{1}};
    const auto deadline = Deadline::after(half + extra, TimePoint::min());

    CHECK(deadline.expires_at() == expected);
    CHECK_FALSE(deadline.expired(TimePoint::min()));
    CHECK(deadline.remaining(TimePoint::min()) == half + extra);
}

} // 命名空间
