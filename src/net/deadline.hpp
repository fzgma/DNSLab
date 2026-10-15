#pragma once

#include <chrono>
#include <cstddef>
#include <expected>
#include <string_view>

namespace dnslab::net {

enum class TimeoutInputErrorCode {
    EmptyValue,
    InvalidCharacter,
    OutOfRange,
};

struct TimeoutInputError {
    TimeoutInputErrorCode code;
    // InvalidCharacter identifies the original byte; other errors use zero.
    std::size_t offset;
};

[[nodiscard]] std::expected<std::chrono::milliseconds, TimeoutInputError>
parse_timeout_ms(std::string_view input) noexcept;

class Deadline {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    explicit Deadline(TimePoint expires_at) noexcept;

    // Nonpositive budgets expire at started_at; positive overflow saturates.
    [[nodiscard]] static Deadline after(
        std::chrono::milliseconds budget, TimePoint started_at = Clock::now()) noexcept;

    [[nodiscard]] TimePoint expires_at() const noexcept;
    [[nodiscard]] bool expired(TimePoint now = Clock::now()) const noexcept;

    // Positive fractions round up; elapsed deadlines return zero.
    [[nodiscard]] std::chrono::milliseconds remaining(
        TimePoint now = Clock::now()) const noexcept;

private:
    const TimePoint expires_at_;
};

} // namespace dnslab::net
