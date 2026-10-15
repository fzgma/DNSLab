#pragma once

#include "net/deadline.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dnslab::net {

enum class EncryptedTransport { Doh, Dot };

struct EncryptedEndpoint {
    EncryptedTransport transport;
    // Canonical HTTPS URL for DoH; canonical host:port (bracketed IPv6) for DoT.
    std::string address;
    bool operator==(const EncryptedEndpoint&) const = default;
};

struct TlsOptions {
    // Empty selects system trust. An explicit CA file never disables verification.
    std::string ca_file{};
};

enum class EncryptedErrorCode {
    InvalidEndpoint,
    InvalidTlsOptions,
    InvalidMessageLength,
    BackendUnavailable,
    Backend,
    CertificateVerification,
    TimedOut,
    HttpStatus,
    InvalidContentType,
    ConnectionClosed,
};

struct EncryptedError {
    EncryptedErrorCode code;
    int backend_code{}; // Original CURLcode; zero for checks made by DNSLab.
    long http_status{};
    std::size_t offset{}; // Original input byte for endpoint errors; otherwise zero.
};

// File/readability and PEM envelope checks only. X.509 semantics remain the TLS
// backend's responsibility; this never imports certificates into the OS store.
[[nodiscard]] std::expected<void, EncryptedError>
validate_tls_options(const TlsOptions& tls);

[[nodiscard]] std::expected<EncryptedEndpoint, EncryptedError>
parse_doh_endpoint(std::string_view input);

[[nodiscard]] std::expected<EncryptedEndpoint, EncryptedError>
parse_dot_endpoint(std::string_view input);

// A fresh, verified TLS connection per exchange. No proxy, redirect or plaintext
// fallback. The same deadline covers name resolution, TLS and all message I/O.
// DoH sends a POST body; DoT adds/removes the two-byte DNS-over-TCP length prefix.
[[nodiscard]] std::expected<std::vector<std::byte>, EncryptedError>
exchange_encrypted(const EncryptedEndpoint& endpoint, std::span<const std::byte> query,
                   const Deadline& deadline, const TlsOptions& tls = {});

} // namespace dnslab::net
