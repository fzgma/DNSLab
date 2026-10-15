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
    // 偏移按原始输入字节计数；长度错误定位违规标签起点。
    // NumericOnlyName 针对整个输入，偏移固定为零。
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
    // 不支持的查询类型或类别不涉及具体标签，索引固定为零。
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
    PacketTooShort, // 偏移为报文实际长度。
    PacketTooLarge, // 偏移为最大报文长度 65535。
    SectionCountMismatch, // 偏移为缺失条目所在的报文末尾。
    InvalidRdataLength, // 偏移为 RDLENGTH 字段首字节。
    RdataLengthMismatch, // 偏移为 RDATA 字段首字节。
    TrailingData, // 偏移为首个未消费的字节。
};

struct DnsParseError {
    DnsParseErrorCode code;
    std::size_t offset;
};

} // 命名空间 dnslab::dns
