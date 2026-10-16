#include "dns/wire_codec.hpp"

#include "dns/byte_utils.hpp"
#include "dns/name_codec.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace dnslab::dns {
namespace {

/// 从当前游标读取 16 位字段，仅在读取成功后推进游标。
std::expected<std::uint16_t, DnsParseError>
read_next_u16(std::span<const std::byte> packet, std::size_t& cursor) {
    auto value = read_u16_be(packet, cursor);
    if (value) {
        cursor += 2;
    }
    return value;
}

/// 从当前游标读取 32 位字段，仅在读取成功后推进游标。
std::expected<std::uint32_t, DnsParseError>
read_next_u32(std::span<const std::byte> packet, std::size_t& cursor) {
    auto value = read_u32_be(packet, cursor);
    if (value) {
        cursor += 4;
    }
    return value;
}

/// 解析问题名称、类型和类别，保留未知类型及类别的原始数值。
std::expected<DnsQuestion, DnsParseError>
parse_question(std::span<const std::byte> packet, std::size_t& cursor) {
    auto name = decode_name(packet, cursor);
    if (!name) {
        return std::unexpected(name.error());
    }
    cursor += name->consumed;

    const auto type = read_next_u16(packet, cursor);
    if (!type) {
        return std::unexpected(type.error());
    }
    const auto qclass = read_next_u16(packet, cursor);
    if (!qclass) {
        return std::unexpected(qclass.error());
    }
    return DnsQuestion{std::move(name->name), *type, *qclass};
}

/// 展开嵌入 RDATA 的名称，只有原编码完整落在该字段内才推进局部游标。
std::expected<DnsName, DnsParseError>
read_rdata_name(std::span<const std::byte> packet, std::size_t& cursor,
                std::size_t rdata_end, std::size_t rdata_start) {
    // 压缩目标以整个报文为基准；解码错误保留原偏移，成功后单独约束原路径长度。
    auto decoded = decode_name(packet, cursor);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    if (decoded->consumed > rdata_end - cursor) {
        return std::unexpected(DnsParseError{
            DnsParseErrorCode::RdataLengthMismatch, rdata_start});
    }
    cursor += decoded->consumed;
    return std::move(decoded->name);
}

/// 按字符字符串的长度字节拆分 TXT，保留空段、分段边界和任意原始字节。
std::expected<TxtData, DnsParseError>
parse_txt(std::span<const std::byte> bytes, std::size_t rdata_start,
           std::size_t rdlength_offset) {
    if (bytes.empty()) {
        return std::unexpected(DnsParseError{
            DnsParseErrorCode::InvalidRdataLength, rdlength_offset});
    }
    TxtData result;
    std::size_t cursor = 0;
    while (cursor < bytes.size()) {
        const auto length = std::to_integer<unsigned char>(bytes[cursor++]);
        if (length > bytes.size() - cursor) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::RdataLengthMismatch, rdata_start});
        }
        const auto string_bytes = bytes.subspan(cursor, length);
        result.strings.emplace_back(string_bytes.begin(), string_bytes.end());
        cursor += length;
    }
    return result;
}

/// 解析 SOA 的两个可压缩名称与五个完整大端整数，拒绝借用后续记录字节。
std::expected<SoaData, DnsParseError>
parse_soa(std::span<const std::byte> packet, std::size_t rdata_start,
           std::size_t rdata_end, std::size_t rdlength_offset) {
    auto cursor = rdata_start;
    auto mname = read_rdata_name(packet, cursor, rdata_end, rdata_start);
    if (!mname) {
        return std::unexpected(mname.error());
    }
    auto rname = read_rdata_name(packet, cursor, rdata_end, rdata_start);
    if (!rname) {
        return std::unexpected(rname.error());
    }
    constexpr std::size_t integer_bytes = 5 * sizeof(std::uint32_t);
    if (rdata_end - cursor < integer_bytes) {
        return std::unexpected(DnsParseError{
            DnsParseErrorCode::InvalidRdataLength, rdlength_offset});
    }
    if (rdata_end - cursor > integer_bytes) {
        return std::unexpected(DnsParseError{
            DnsParseErrorCode::RdataLengthMismatch, rdata_start});
    }
    SoaData result{std::move(*mname), std::move(*rname)};
    // 尾部长度已经精确核对，五次定长读取均位于本条 RDATA 内。
    for (auto* field : {&result.serial, &result.refresh, &result.retry,
                        &result.expire, &result.minimum}) {
        *field = *read_next_u32(packet, cursor);
    }
    return result;
}

/// 解析一条资源记录，并按类型和类别解码或保留原始 RDATA。
std::expected<ResourceRecord, DnsParseError>
parse_record(std::span<const std::byte> packet, std::size_t& cursor) {
    auto owner = decode_name(packet, cursor);
    if (!owner) {
        return std::unexpected(owner.error());
    }
    cursor += owner->consumed;

    const auto type = read_next_u16(packet, cursor);
    if (!type) {
        return std::unexpected(type.error());
    }
    const auto rr_class = read_next_u16(packet, cursor);
    if (!rr_class) {
        return std::unexpected(rr_class.error());
    }
    const auto ttl = read_next_u32(packet, cursor);
    if (!ttl) {
        return std::unexpected(ttl.error());
    }
    const auto rdlength_offset = cursor;
    const auto rdlength = read_next_u16(packet, cursor);
    if (!rdlength) {
        return std::unexpected(rdlength.error());
    }

    // 先保证声明的 RDATA 全部位于报文内，再验证已知类型的固定长度。
    const auto rdata_start = cursor;
    if (*rdlength > packet.size() - rdata_start) {
        return std::unexpected(DnsParseError{
            DnsParseErrorCode::FieldOutOfBounds, rdata_start});
    }
    const auto bytes = packet.subspan(rdata_start, *rdlength);
    RData rdata = OpaqueData{};
    if (*type == 1 && *rr_class == 1) {
        if (*rdlength != 4) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::InvalidRdataLength, rdlength_offset});
        }
        AData address{};
        std::copy(bytes.begin(), bytes.end(), address.address.begin());
        rdata = address;
    } else if (*type == 28 && *rr_class == 1) {
        if (*rdlength != 16) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::InvalidRdataLength, rdlength_offset});
        }
        AaaaData address{};
        std::copy(bytes.begin(), bytes.end(), address.address.begin());
        rdata = address;
    } else if (*type == 2 || *type == 5 || *type == 12) {
        auto name_cursor = rdata_start;
        auto name = read_rdata_name(packet, name_cursor, rdata_start + *rdlength, rdata_start);
        if (!name) {
            return std::unexpected(name.error());
        }
        if (name_cursor != rdata_start + *rdlength) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::RdataLengthMismatch, rdata_start});
        }
        rdata = NameData{std::move(*name)};
    } else if (*type == 15) {
        if (bytes.size() < 2) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::InvalidRdataLength, rdlength_offset});
        }
        auto name_cursor = rdata_start + 2;
        auto exchange = read_rdata_name(packet, name_cursor,
                                        rdata_start + *rdlength, rdata_start);
        if (!exchange) {
            return std::unexpected(exchange.error());
        }
        if (name_cursor != rdata_start + *rdlength) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::RdataLengthMismatch, rdata_start});
        }
        rdata = MxData{*read_u16_be(bytes, 0), std::move(*exchange)};
    } else if (*type == 16) {
        auto text = parse_txt(bytes, rdata_start, rdlength_offset);
        if (!text) {
            return std::unexpected(text.error());
        }
        rdata = std::move(*text);
    } else if (*type == 6) {
        auto soa = parse_soa(packet, rdata_start, rdata_start + *rdlength, rdlength_offset);
        if (!soa) {
            return std::unexpected(soa.error());
        }
        rdata = std::move(*soa);
    } else {
        rdata = OpaqueData{Packet{bytes.begin(), bytes.end()}};
    }

    cursor += *rdlength;
    return ResourceRecord{std::move(owner->name), *type, *rr_class, *ttl,
                          std::move(rdata)};
}

/// 逐条读取指定记录区，只有新条目恰好缺失于报文末尾时报告计数不符。
std::expected<void, DnsParseError>
parse_records(std::span<const std::byte> packet, std::size_t& cursor,
              std::uint16_t count, std::vector<ResourceRecord>& records) {
    for (std::size_t index = 0; index < count; ++index) {
        if (cursor == packet.size()) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::SectionCountMismatch, cursor});
        }
        auto record = parse_record(packet, cursor);
        if (!record) {
            return std::unexpected(record.error());
        }
        records.push_back(std::move(*record));
    }
    return {};
}

} // 命名空间

/// 校验报文总长后解析四个记录区，并拒绝未被计数覆盖的尾随字节。
std::expected<DnsMessage, DnsParseError>
parse_message(std::span<const std::byte> packet) {
    constexpr std::size_t header_length = 12;
    constexpr std::size_t max_packet_length = 65535;
    if (packet.size() < header_length) {
        return std::unexpected(DnsParseError{
            DnsParseErrorCode::PacketTooShort, packet.size()});
    }
    if (packet.size() > max_packet_length) {
        return std::unexpected(DnsParseError{
            DnsParseErrorCode::PacketTooLarge, max_packet_length});
    }

    // 上方已保证固定报文头完整，因此这些定长读取不会失败。
    DnsMessage message;
    message.header = DnsHeader{*read_u16_be(packet, 0), *read_u16_be(packet, 2)};
    const std::array counts{*read_u16_be(packet, 4), *read_u16_be(packet, 6),
                            *read_u16_be(packet, 8), *read_u16_be(packet, 10)};
    std::size_t cursor = header_length;

    // 计数来自不可信报文，逐条追加而不按声明数量提前大量分配。
    for (std::size_t index = 0; index < counts[0]; ++index) {
        if (cursor == packet.size()) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::SectionCountMismatch, cursor});
        }
        auto question = parse_question(packet, cursor);
        if (!question) {
            return std::unexpected(question.error());
        }
        message.questions.push_back(std::move(*question));
    }

    const std::array sections{&message.answers, &message.authority,
                              &message.additional};
    for (std::size_t index = 0; index < sections.size(); ++index) {
        const auto result = parse_records(packet, cursor, counts[index + 1],
                                           *sections[index]);
        if (!result) {
            return std::unexpected(result.error());
        }
    }
    if (cursor != packet.size()) {
        return std::unexpected(DnsParseError{
            DnsParseErrorCode::TrailingData, cursor});
    }
    return message;
}

} // 命名空间 dnslab::dns
