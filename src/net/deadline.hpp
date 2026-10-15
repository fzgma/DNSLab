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
    // 非法字符定位原始输入字节，其他错误的偏移为零。
    std::size_t offset;
};

/// 将纯 ASCII 十进制输入解析为 100 至 30000 毫秒的查询预算。
[[nodiscard]] std::expected<std::chrono::milliseconds, TimeoutInputError>
parse_timeout_ms(std::string_view input) noexcept;

class Deadline {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    /// 从绝对时间点构造不可续期的截止时间。
    explicit Deadline(TimePoint expires_at) noexcept;

    /// 将预算换算为截止时间，非正预算立即到期，正溢出饱和到时钟上限。
    [[nodiscard]] static Deadline after(
        std::chrono::milliseconds budget, TimePoint started_at = Clock::now()) noexcept;

    /// 返回构造时确定的绝对截止时间。
    [[nodiscard]] TimePoint expires_at() const noexcept;
    /// 判断指定时间是否已经到达或超过截止时间。
    [[nodiscard]] bool expired(TimePoint now = Clock::now()) const noexcept;

    /// 返回向上取整的剩余毫秒数，到期为零，超出表示范围时饱和。
    [[nodiscard]] std::chrono::milliseconds remaining(
        TimePoint now = Clock::now()) const noexcept;

private:
    const TimePoint expires_at_;
};

} // 命名空间 dnslab::net
