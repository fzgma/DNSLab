#pragma once

#include <cstddef>

namespace dnslab::dns {

enum class DnsParseErrorCode {
    FieldOutOfBounds,
};

struct DnsParseError {
    DnsParseErrorCode code;
    std::size_t offset;
};

} // namespace dnslab::dns
