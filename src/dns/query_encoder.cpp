#include "dns/wire_codec.hpp"

#include "dns/byte_utils.hpp"
#include "dns/name_codec.hpp"

#include <cstdint>
#include <expected>

namespace dnslab::dns {

/// 校验问题后生成仅含一个问题、可选 RD 标志的标准查询报文。
std::expected<Packet, DnsEncodeError>
encode_query(const DnsQuestion& question, std::uint16_t transaction_id,
             bool recursion_desired) {
    const auto encoded_name = encode_name(question.name);
    if (!encoded_name) {
        return std::unexpected(encoded_name.error());
    }
    if (question.type != 1 && question.type != 28) {
        return std::unexpected(DnsEncodeError{
            DnsEncodeErrorCode::UnsupportedQueryType, 0});
    }
    if (question.qclass != 1) {
        return std::unexpected(DnsEncodeError{
            DnsEncodeErrorCode::UnsupportedQueryClass, 0});
    }

    Packet packet;
    packet.reserve(12 + encoded_name->bytes.size() + 4);
    append_u16_be(packet, transaction_id);
    append_u16_be(packet, recursion_desired ? std::uint16_t{0x0100} : std::uint16_t{0});
    append_u16_be(packet, 1); // 问题区只有一个条目。
    append_u16_be(packet, 0); // 应答区、权威区和附加区均为空。
    append_u16_be(packet, 0);
    append_u16_be(packet, 0);
    packet.insert(packet.end(), encoded_name->bytes.begin(), encoded_name->bytes.end());
    append_u16_be(packet, question.type);
    append_u16_be(packet, question.qclass);
    return packet;
}

} // 命名空间 dnslab::dns
