#pragma once

#include <cstddef>

namespace dnslab::dns {

enum class NameInputErrorCode {
    EmptyName,
    EmptyLabel,
    LabelTooLong,
    NameTooLong,
    InvalidCharacter,
    HyphenAtBoundary,
};

struct NameInputError {
    NameInputErrorCode code;
    // Byte offset in the input; length errors identify the offending label start.
    std::size_t offset;
};

enum class DnsEncodeErrorCode {
    EmptyLabel,
    LabelTooLong,
    NameTooLong,
};

struct DnsEncodeError {
    DnsEncodeErrorCode code;
    std::size_t label_index;
};

enum class DnsParseErrorCode {
    FieldOutOfBounds,
    NameOutOfBounds,
    ReservedLabelEncoding,
    ExpandedNameTooLong,
    // Transitional error until compression decoding is implemented separately.
    CompressionNotSupported,
};

struct DnsParseError {
    DnsParseErrorCode code;
    std::size_t offset;
};

} // namespace dnslab::dns
