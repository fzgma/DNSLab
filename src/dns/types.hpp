#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace dnslab::dns {

using Packet = std::vector<std::byte>;

struct DnsName {
    // An empty label list is the root; labels otherwise retain raw octets.
    std::vector<std::string> labels;
};

struct EncodedName {
    Packet bytes;
};

struct DecodedName {
    DnsName name;
    std::size_t consumed;
};

} // namespace dnslab::dns
