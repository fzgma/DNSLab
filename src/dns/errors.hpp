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
    NumericOnlyName,
};

struct NameInputError {
    NameInputErrorCode code;
    // Byte offset in the input; length errors identify the offending label start.
    // NumericOnlyName identifies the entire input and uses offset zero.
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
    CompressionPointerTruncated,
    CompressionPointerOutOfBounds,
    CompressionPointerNotBackward,
    CompressionLoop,
    ExpandedNameTooLong,
};

struct DnsParseError {
    DnsParseErrorCode code;
    std::size_t offset;
};

} // namespace dnslab::dns
