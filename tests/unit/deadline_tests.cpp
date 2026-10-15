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

void check_input_error(std::string_view input, TimeoutInputErrorCode code,
                       std::size_t offset) {
    const auto result = parse_timeout_ms(input);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == code);
    CHECK(result.error().offset == offset);
}

TEST_CASE("Timeout input accepts inclusive limits and leading zeroes",
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

TEST_CASE("Timeout input rejects empty and out-of-range values without overflow",
          "[deadline][input]") {
    check_input_error("", TimeoutInputErrorCode::EmptyValue, 0);
    for (const auto input : {"0", "0000", "99", "30001", "99999999999999999999"}) {
        CAPTURE(input);
        check_input_error(input, TimeoutInputErrorCode::OutOfRange, 0);
    }
    check_input_error(std::string(1000, '9'), TimeoutInputErrorCode::OutOfRange, 0);
}

TEST_CASE("Timeout input checks all bytes before reporting a range error",
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

TEST_CASE("Deadline stores an absolute expiration without changing on reads",
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

TEST_CASE("Deadline after preserves ordinary budgets across the epoch",
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

TEST_CASE("Deadline expires exactly at its cutoff and stays at zero afterward",
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

TEST_CASE("Positive remaining fractions round up to milliseconds",
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

TEST_CASE("UDP work and TCP fallback share one unchanged deadline",
          "[deadline]") {
    const auto started_at = TimePoint{} + 100s;
    const auto deadline = Deadline::after(1500ms, started_at);

    CHECK(deadline.remaining(started_at) == 1500ms);
    CHECK(deadline.remaining(started_at + 400ms) == 1100ms); // UDP completes.
    CHECK(deadline.remaining(started_at + 900ms) == 600ms); // TCP connects.
    CHECK(deadline.remaining(started_at + 1200ms) == 300ms); // Partial receive.
    CHECK(deadline.remaining(started_at + 1499ms) == 1ms);
    CHECK(deadline.expired(started_at + 1500ms));
    CHECK(deadline.expires_at() == started_at + 1500ms);
}

TEST_CASE("Each server has an independent deadline",
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

TEST_CASE("Nonpositive budgets expire immediately without arithmetic",
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

TEST_CASE("Deadline creation saturates at the maximum time point",
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

TEST_CASE("Deadlines support time points near the minimum clock value",
          "[deadline][bounds]") {
    const auto started_at = TimePoint::min();
    const auto deadline = Deadline::after(1ms, started_at);

    CHECK(deadline.expires_at() == started_at + 1ms);
    CHECK(deadline.remaining(started_at) == 1ms);
    CHECK(deadline.expired(started_at + 1ms));
    CHECK(Deadline{TimePoint::min()}.remaining(TimePoint::max()) == 0ms);
}

TEST_CASE("Remaining time handles the full signed clock range",
          "[deadline][bounds]") {
    // Split max - min into two representable halves plus one tick; this avoids
    // overflowing the signed duration while constructing the expected result.
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

TEST_CASE("A large budget can cross the epoch without premature saturation",
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

} // namespace
