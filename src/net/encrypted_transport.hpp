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
    // DoH 保存规范 HTTPS URL；DoT 保存带端口的主机，IPv6 使用方括号。
    std::string address;
    /// 比较传输方式与规范地址文本，判断是否为同一加密端点。
    bool operator==(const EncryptedEndpoint&) const = default;
};

struct TlsOptions {
    // 空值使用系统信任；显式 CA 文件也不会禁用证书验证。
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
    int backend_code{}; // 保留原始 CURLcode；DNSLab 自身检查失败时为零。
    long http_status{};
    std::size_t offset{}; // 端点错误定位原输入字节，其他错误为零。
};

/// 检查 CA 文件可读性及 PEM 基本边界，不替代 TLS 库的 X.509 验证。
// 该检查不向操作系统证书库导入任何证书。
[[nodiscard]] std::expected<void, EncryptedError>
validate_tls_options(const TlsOptions& tls);

/// 校验 HTTPS 目标并规范化主机和端口，保留路径与查询参数。
[[nodiscard]] std::expected<EncryptedEndpoint, EncryptedError>
parse_doh_endpoint(std::string_view input);

/// 校验 DoT 主机或字面 IP，并补充默认 TLS 端口 853。
[[nodiscard]] std::expected<EncryptedEndpoint, EncryptedError>
parse_dot_endpoint(std::string_view input);

/// 在同一截止时间内建立经验证的 TLS 连接并交换一条 DoH 或 DoT 消息。
// 每次调用新建连接，禁止代理、重定向与明文回退；预算覆盖解析、握手和收发。
// DoH 发送 POST 正文；DoT 添加或移除两字节 DNS 长度前缀。
[[nodiscard]] std::expected<std::vector<std::byte>, EncryptedError>
exchange_encrypted(const EncryptedEndpoint& endpoint, std::span<const std::byte> query,
                   const Deadline& deadline, const TlsOptions& tls = {});

} // 命名空间 dnslab::net
