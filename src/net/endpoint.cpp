#include "net/endpoint.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <utility>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace dnslab::net {
namespace {

std::optional<Ipv4Address> parse_ipv4(std::string_view text) {
    Ipv4Address address{};
    std::size_t start = 0;
    for (std::size_t index = 0; index < address.size(); ++index) {
        const auto dot = text.find('.', start);
        if ((index == address.size() - 1) != (dot == std::string_view::npos)) {
            return std::nullopt;
        }
        const auto end = dot == std::string_view::npos ? text.size() : dot;
        const auto part = text.substr(start, end - start);
        if (part.empty() || part.size() > 3 || (part.size() > 1 && part.front() == '0')) {
            return std::nullopt;
        }
        unsigned int value = 0;
        for (const char digit : part) {
            if (digit < '0' || digit > '9') {
                return std::nullopt;
            }
            value = value * 10 + static_cast<unsigned int>(digit - '0');
        }
        if (value > 255) {
            return std::nullopt;
        }
        address[index] = static_cast<std::byte>(value);
        if (dot != std::string_view::npos) {
            start = dot + 1;
        }
    }
    return address;
}

std::optional<Ipv6Address> parse_ipv6(std::string_view text) {
    if (text.empty() || text.size() >= INET6_ADDRSTRLEN) {
        return std::nullopt;
    }
    // Enforce the same decimal IPv4 rules for a mixed IPv6 address on all OSes.
    if (text.find('.') != std::string_view::npos) {
        const auto colon = text.rfind(':');
        if (colon == std::string_view::npos || !parse_ipv4(text.substr(colon + 1))) {
            return std::nullopt;
        }
    }
    in6_addr native_address{};
    const std::string terminated{text};
    if (::inet_pton(AF_INET6, terminated.c_str(), &native_address) != 1) {
        return std::nullopt;
    }
    Ipv6Address address{};
    static_assert(sizeof(native_address) == sizeof(address));
    std::memcpy(address.data(), &native_address, address.size());
    return address;
}

std::expected<std::uint16_t, EndpointInputError>
parse_port(std::string_view text, std::size_t offset) {
    if (text.empty()) {
        return std::unexpected(EndpointInputError{
            EndpointInputErrorCode::MissingPort, offset});
    }
    for (std::size_t index = 0; index < text.size(); ++index) {
        if (text[index] < '0' || text[index] > '9') {
            return std::unexpected(EndpointInputError{
                EndpointInputErrorCode::InvalidPort, offset + index});
        }
    }
    unsigned int port = 0;
    for (const char digit : text) {
        const auto value = static_cast<unsigned int>(digit - '0');
        if (port > (65535U - value) / 10U) {
            return std::unexpected(EndpointInputError{
                EndpointInputErrorCode::PortOutOfRange, offset});
        }
        port = port * 10 + value;
    }
    if (port == 0) {
        return std::unexpected(EndpointInputError{
            EndpointInputErrorCode::PortOutOfRange, offset});
    }
    return static_cast<std::uint16_t>(port);
}

std::string format_ipv6(const Ipv6Address& address) {
    std::array<std::uint16_t, 8> words{};
    for (std::size_t index = 0; index < words.size(); ++index) {
        words[index] = static_cast<std::uint16_t>(
            (std::to_integer<unsigned int>(address[index * 2]) << 8) |
            std::to_integer<unsigned int>(address[index * 2 + 1]));
    }
    std::size_t best_start = words.size();
    std::size_t best_length = 0;
    for (std::size_t index = 0; index < words.size();) {
        if (words[index] != 0) {
            ++index;
            continue;
        }
        const auto start = index;
        while (index < words.size() && words[index] == 0) {
            ++index;
        }
        const auto length = index - start;
        if (length >= 2 && length > best_length) {
            best_start = start;
            best_length = length;
        }
    }

    std::string result;
    for (std::size_t index = 0; index < words.size();) {
        if (index == best_start) {
            result += "::";
            index += best_length;
            continue;
        }
        if (!result.empty() && result.back() != ':') {
            result.push_back(':');
        }
        std::array<char, 4> buffer{};
        const auto conversion = std::to_chars(buffer.data(), buffer.data() + buffer.size(),
                                               words[index], 16);
        result.append(buffer.data(), conversion.ptr);
        ++index;
    }
    return result;
}

} // namespace

IpFamily Endpoint::family() const noexcept {
    return std::holds_alternative<Ipv4Address>(address) ? IpFamily::V4 : IpFamily::V6;
}

std::expected<Endpoint, EndpointInputError> parse_endpoint(std::string_view input) {
    if (input.empty()) {
        return std::unexpected(EndpointInputError{EndpointInputErrorCode::EmptyInput, 0});
    }
    for (std::size_t index = 0; index < input.size(); ++index) {
        const auto value = static_cast<unsigned char>(input[index]);
        if (value <= 0x20 || value >= 0x7f || value == '%') {
            return std::unexpected(EndpointInputError{
                EndpointInputErrorCode::InvalidCharacter, index});
        }
    }

    std::string_view address_text = input;
    std::size_t address_offset = 0;
    std::optional<std::size_t> port_offset;
    bool ipv6 = false;
    if (input.front() == '[') {
        const auto close = input.find(']');
        if (close == std::string_view::npos) {
            return std::unexpected(EndpointInputError{
                EndpointInputErrorCode::InvalidFormat, input.size()});
        }
        address_offset = 1;
        address_text = input.substr(1, close - 1);
        ipv6 = true;
        if (close == input.size() - 1) {
            return std::unexpected(EndpointInputError{
                EndpointInputErrorCode::MissingPort, input.size()});
        }
        if (input[close + 1] != ':') {
            return std::unexpected(EndpointInputError{
                EndpointInputErrorCode::InvalidFormat, close + 1});
        }
        port_offset = close + 2;
    } else {
        const auto bracket = input.find_first_of("[]");
        if (bracket != std::string_view::npos) {
            return std::unexpected(EndpointInputError{
                EndpointInputErrorCode::InvalidFormat, bracket});
        }
        const auto colon = input.find(':');
        if (colon != std::string_view::npos) {
            if (input.find(':', colon + 1) == std::string_view::npos) {
                address_text = input.substr(0, colon);
                port_offset = colon + 1;
            } else {
                ipv6 = true;
            }
        }
    }

    Endpoint endpoint;
    if (ipv6) {
        const auto address = parse_ipv6(address_text);
        if (!address) {
            return std::unexpected(EndpointInputError{
                EndpointInputErrorCode::InvalidAddress, address_offset});
        }
        endpoint.address = *address;
    } else {
        const auto address = parse_ipv4(address_text);
        if (!address) {
            return std::unexpected(EndpointInputError{
                EndpointInputErrorCode::InvalidAddress, address_offset});
        }
        endpoint.address = *address;
    }
    if (port_offset) {
        const auto port = parse_port(input.substr(*port_offset), *port_offset);
        if (!port) {
            return std::unexpected(port.error());
        }
        endpoint.port = *port;
    }
    return endpoint;
}

std::string format_endpoint(const Endpoint& endpoint) {
    std::string result;
    if (const auto* address = std::get_if<Ipv4Address>(&endpoint.address)) {
        for (const auto byte : *address) {
            if (!result.empty()) {
                result.push_back('.');
            }
            result += std::to_string(std::to_integer<unsigned int>(byte));
        }
    } else {
        result = "[" + format_ipv6(std::get<Ipv6Address>(endpoint.address)) + "]";
    }
    return result + ":" + std::to_string(endpoint.port);
}

std::expected<std::vector<Endpoint>, EndpointListError>
parse_unique_endpoints(std::span<const std::string_view> inputs) {
    std::vector<Endpoint> endpoints;
    for (std::size_t index = 0; index < inputs.size(); ++index) {
        auto endpoint = parse_endpoint(inputs[index]);
        if (!endpoint) {
            return std::unexpected(EndpointListError{endpoint.error(), index, std::nullopt});
        }
        const auto existing = std::find(endpoints.begin(), endpoints.end(), *endpoint);
        if (existing != endpoints.end()) {
            return std::unexpected(EndpointListError{
                {EndpointInputErrorCode::DuplicateEndpoint, 0}, index,
                static_cast<std::size_t>(existing - endpoints.begin())});
        }
        endpoints.push_back(std::move(*endpoint));
    }
    return endpoints;
}

} // namespace dnslab::net
