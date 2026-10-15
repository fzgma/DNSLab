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
    UnsupportedQueryType,
    UnsupportedQueryClass,
};

struct DnsEncodeError {
    DnsEncodeErrorCode code;
    // Unsupported query type/class errors use zero; no label is implicated.
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
    PacketTooShort, // offset is packet.size().
    PacketTooLarge, // offset is the maximum packet size, 65535.
    SectionCountMismatch, // offset is the missing entry's cursor at packet end.
    InvalidRdataLength, // offset is the RDLENGTH field's first byte.
    RdataLengthMismatch, // offset is the RDATA field's first byte.
    TrailingData, // offset is the first unconsumed byte.
};

struct DnsParseError {
    DnsParseErrorCode code;
    std::size_t offset;
};

} // namespace dnslab::dns
