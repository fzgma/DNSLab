#include "net/deadline.hpp"

#include <cstdint>
#include <limits>
#include <ratio>
#include <type_traits>

namespace dnslab::net {
namespace {

using ClockDuration = Deadline::Clock::duration;
using ClockRep = ClockDuration::rep;
using Milliseconds = std::chrono::milliseconds;
using Count = std::uintmax_t;
using MillisecondsToTicks = std::ratio_divide<std::milli, ClockDuration::period>;

static_assert(std::is_integral_v<ClockRep> && std::is_signed_v<ClockRep>);
static_assert(std::is_integral_v<Milliseconds::rep> &&
              std::is_signed_v<Milliseconds::rep>);
static_assert(std::numeric_limits<ClockRep>::digits < std::numeric_limits<Count>::digits);
static_assert(std::numeric_limits<Milliseconds::rep>::digits <
              std::numeric_limits<Count>::digits);
static_assert(MillisecondsToTicks::den == 1,
              "Deadline requires a steady clock that represents milliseconds exactly");

constexpr Count ticks_per_millisecond = static_cast<Count>(MillisecondsToTicks::num);

// Converting to unsigned before subtraction also handles min-to-max distances.
Count tick_distance(Deadline::TimePoint later, Deadline::TimePoint earlier) noexcept {
    return static_cast<Count>(later.time_since_epoch().count()) -
           static_cast<Count>(earlier.time_since_epoch().count());
}

} // namespace

std::expected<std::chrono::milliseconds, TimeoutInputError>
parse_timeout_ms(std::string_view input) noexcept {
    if (input.empty()) {
        return std::unexpected(TimeoutInputError{TimeoutInputErrorCode::EmptyValue, 0});
    }
    for (std::size_t index = 0; index < input.size(); ++index) {
        if (input[index] < '0' || input[index] > '9') {
            return std::unexpected(TimeoutInputError{
                TimeoutInputErrorCode::InvalidCharacter, index});
        }
    }

    constexpr std::uint32_t maximum = 30000;
    std::uint32_t value = 0;
    for (const char character : input) {
        const auto digit = static_cast<std::uint32_t>(character - '0');
        if (value > (maximum - digit) / 10) {
            return std::unexpected(TimeoutInputError{TimeoutInputErrorCode::OutOfRange, 0});
        }
        value = value * 10 + digit;
    }
    if (value < 100) {
        return std::unexpected(TimeoutInputError{TimeoutInputErrorCode::OutOfRange, 0});
    }
    return Milliseconds{value};
}

Deadline::Deadline(TimePoint expires_at) noexcept : expires_at_(expires_at) {}

Deadline Deadline::after(Milliseconds budget, TimePoint started_at) noexcept {
    if (budget <= Milliseconds::zero()) {
        return Deadline{started_at};
    }

    const auto available = tick_distance(TimePoint::max(), started_at);
    const auto milliseconds = static_cast<Count>(budget.count());
    if (milliseconds > available / ticks_per_millisecond) {
        return Deadline{TimePoint::max()};
    }

    const auto ticks = milliseconds * ticks_per_millisecond;
    const auto absolute_ticks =
        static_cast<Count>(started_at.time_since_epoch().count()) + ticks;
    // The checked result fits ClockRep; C++23 integral conversion preserves it
    // even when unsigned addition wrapped while crossing a negative epoch.
    return Deadline{TimePoint{ClockDuration{static_cast<ClockRep>(absolute_ticks)}}};
}

Deadline::TimePoint Deadline::expires_at() const noexcept {
    return expires_at_;
}

bool Deadline::expired(TimePoint now) const noexcept {
    return now >= expires_at_;
}

std::chrono::milliseconds Deadline::remaining(TimePoint now) const noexcept {
    if (expired(now)) {
        return Milliseconds::zero();
    }

    const auto ticks = tick_distance(expires_at_, now);
    const auto whole_milliseconds = ticks / ticks_per_millisecond;
    constexpr auto maximum = static_cast<Count>(Milliseconds::max().count());
    if (whole_milliseconds >= maximum) {
        return Milliseconds::max();
    }

    const auto rounded = whole_milliseconds +
                         (ticks % ticks_per_millisecond != 0 ? Count{1} : Count{0});
    return Milliseconds{static_cast<Milliseconds::rep>(rounded)};
}

} // namespace dnslab::net
