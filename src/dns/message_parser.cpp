#include "dns/wire_codec.hpp"

#include "dns/byte_utils.hpp"
#include "dns/name_codec.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace dnslab::dns {
namespace {

std::expected<std::uint16_t, DnsParseError>
read_next_u16(std::span<const std::byte> packet, std::size_t& cursor) {
    auto value = read_u16_be(packet, cursor);
    if (value) {
        cursor += 2;
    }
    return value;
}

std::expected<std::uint32_t, DnsParseError>
read_next_u32(std::span<const std::byte> packet, std::size_t& cursor) {
    auto value = read_u32_be(packet, cursor);
    if (value) {
        cursor += 4;
    }
    return value;
}

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
    } else if (*type == 5) {
        auto name = decode_name(packet, rdata_start);
        if (!name) {
            return std::unexpected(name.error());
        }
        if (name->consumed != *rdlength) {
            return std::unexpected(DnsParseError{
                DnsParseErrorCode::RdataLengthMismatch, rdata_start});
        }
        rdata = NameData{std::move(name->name)};
    } else {
        rdata = OpaqueData{Packet{bytes.begin(), bytes.end()}};
    }

    cursor += *rdlength;
    return ResourceRecord{std::move(owner->name), *type, *rr_class, *ttl,
                          std::move(rdata)};
}

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

} // namespace

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

    // The complete fixed header was checked above; these reads cannot fail.
    DnsMessage message;
    message.header = DnsHeader{*read_u16_be(packet, 0), *read_u16_be(packet, 2)};
    const std::array counts{*read_u16_be(packet, 4), *read_u16_be(packet, 6),
                            *read_u16_be(packet, 8), *read_u16_be(packet, 10)};
    std::size_t cursor = header_length;

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

} // namespace dnslab::dns
