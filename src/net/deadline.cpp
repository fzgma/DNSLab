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
              "Deadline 要求单调时钟能够精确表示毫秒");

constexpr Count ticks_per_millisecond = static_cast<Count>(MillisecondsToTicks::num);

/// 先转为无符号计数再求差，以安全覆盖时钟最小值到最大值的距离。
Count tick_distance(Deadline::TimePoint later, Deadline::TimePoint earlier) noexcept {
    return static_cast<Count>(later.time_since_epoch().count()) -
           static_cast<Count>(earlier.time_since_epoch().count());
}

} // 命名空间

/// 先检查所有字符，再以受界乘加验证超时范围和数值溢出。
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

/// 保存绝对截止时间，不在后续等待中重置。
Deadline::Deadline(TimePoint expires_at) noexcept : expires_at_(expires_at) {}

/// 先比较可用时钟跨度，再安全累加预算并处理上限饱和。
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
    // 检查已保证数学结果可由 ClockRep 表示；跨越负时间点时即使无符号加法回绕，
    // C++23 的整数转换仍按同余规则还原该结果。
    return Deadline{TimePoint{ClockDuration{static_cast<ClockRep>(absolute_ticks)}}};
}

/// 读取内部保存的绝对截止时间。
Deadline::TimePoint Deadline::expires_at() const noexcept {
    return expires_at_;
}

/// 将当前时间与固定截止时间比较，截止时刻本身也视为到期。
bool Deadline::expired(TimePoint now) const noexcept {
    return now >= expires_at_;
}

/// 使用无符号差值和整数余数计算剩余毫秒，避免极端时间点溢出。
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

} // 命名空间 dnslab::net
