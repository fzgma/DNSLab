#include "net/encrypted_transport.hpp"

#include "dns/name_codec.hpp"
#include "net/endpoint.hpp"
#include "net/native_socket.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <utility>

namespace dnslab::net {
namespace {

using Packet = std::vector<std::byte>;
constexpr std::size_t minimum_message = 12;
constexpr std::size_t maximum_message = 65535;

/// 构造带原始输入偏移的加密端点参数错误。
EncryptedError invalid_endpoint(std::size_t offset = 0) {
    return {EncryptedErrorCode::InvalidEndpoint, 0, 0, offset};
}

/// 构造不依赖后端错误码的预算耗尽错误。
EncryptedError timeout() { return {EncryptedErrorCode::TimedOut}; }

/// 将一个 ASCII 大写字母转为小写，保持其他字符不变。
char lower_ascii(char value) {
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

/// 复制文本并仅折叠 ASCII 字母大小写。
std::string lowercase(std::string_view input) {
    std::string result{input};
    std::transform(result.begin(), result.end(), result.begin(), lower_ascii);
    return result;
}

/// 拒绝加密地址中的空白、控制字节、非 ASCII、反斜线和片段标记。
std::expected<void, EncryptedError> validate_characters(std::string_view input) {
    if (input.empty()) {
        return std::unexpected(invalid_endpoint());
    }
    for (std::size_t index = 0; index < input.size(); ++index) {
        const auto value = static_cast<unsigned char>(input[index]);
        if (value <= 0x20 || value >= 0x7f || value == '\\' || value == '#') {
            return std::unexpected(invalid_endpoint(index));
        }
    }
    return {};
}

/// 将十进制端口限制在 1 至 65535，并保留原输入中的错误位置。
std::expected<std::uint16_t, EncryptedError>
parse_port(std::string_view input, std::size_t offset) {
    if (input.empty()) {
        return std::unexpected(invalid_endpoint(offset));
    }
    unsigned int result = 0;
    for (std::size_t index = 0; index < input.size(); ++index) {
        const char digit = input[index];
        if (digit < '0' || digit > '9') {
            return std::unexpected(invalid_endpoint(offset + index));
        }
        const auto value = static_cast<unsigned int>(digit - '0');
        if (result > (65535U - value) / 10U) {
            return std::unexpected(invalid_endpoint(offset));
        }
        result = result * 10U + value;
    }
    if (result == 0) {
        return std::unexpected(invalid_endpoint(offset));
    }
    return static_cast<std::uint16_t>(result);
}

/// 识别可能被后端按旧式数字 IP 解释的主机文本。
bool ambiguous_numeric_host(std::string_view host) {
    if (!host.empty() && host.back() == '.') {
        host.remove_suffix(1);
    }
    std::size_t start = 0;
    for (;;) {
        const auto separator = host.find('.', start);
        const auto end = separator == std::string_view::npos ? host.size() : separator;
        auto part = host.substr(start, end - start);
        bool hexadecimal = false;
        if (part.size() > 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X')) {
            hexadecimal = true;
            part.remove_prefix(2);
        }
        // 按当前分段的十进制或十六进制语法检查，防止域名被后端改写为 IP。
        if (part.empty() || !std::all_of(part.begin(), part.end(), [hexadecimal](char digit) {
                return (digit >= '0' && digit <= '9') ||
                    (hexadecimal && ((digit >= 'a' && digit <= 'f') ||
                                     (digit >= 'A' && digit <= 'F')));
            })) {
            return false;
        }
        if (separator == std::string_view::npos) {
            return true;
        }
        start = separator + 1;
    }
}

/// 拆分并校验主机及端口，按传输规则处理 IPv6 方括号与默认端口。
std::expected<std::string, EncryptedError>
parse_authority(std::string_view input, std::uint16_t default_port,
                 std::size_t offset, bool allow_bare_ipv6) {
    if (input.empty()) {
        return std::unexpected(invalid_endpoint(offset));
    }
    const auto forbidden = input.find_first_of("@%/?");
    if (forbidden != std::string_view::npos) {
        return std::unexpected(invalid_endpoint(offset + forbidden));
    }
    std::uint16_t port = default_port;
    std::string_view host = input;
    if (input.front() == '[') {
        const auto close = input.find(']');
        if (close == std::string_view::npos) {
            return std::unexpected(invalid_endpoint(offset + input.size()));
        }
        if (close + 1 < input.size()) {
            if (input[close + 1] != ':') {
                return std::unexpected(invalid_endpoint(offset + close + 1));
            }
            const auto parsed = parse_port(input.substr(close + 2), offset + close + 2);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            port = *parsed;
        }
        const auto address = parse_endpoint(std::string{input.substr(0, close + 1)} +
                                             ":" + std::to_string(port));
        if (!address || address->family() != IpFamily::V6) {
            return std::unexpected(invalid_endpoint(offset + 1));
        }
        return format_endpoint(*address);
    }
    const auto bracket = input.find_first_of("[]");
    if (bracket != std::string_view::npos) {
        return std::unexpected(invalid_endpoint(offset + bracket));
    }
    const auto colon = input.find(':');
    if (colon != std::string_view::npos) {
        if (input.find(':', colon + 1) != std::string_view::npos) {
            if (!allow_bare_ipv6) {
                return std::unexpected(invalid_endpoint(offset));
            }
            auto address = parse_endpoint(input);
            if (!address || address->family() != IpFamily::V6) {
                return std::unexpected(invalid_endpoint(offset));
            }
            address->port = port;
            return format_endpoint(*address);
        }
        host = input.substr(0, colon);
        const auto parsed = parse_port(input.substr(colon + 1), offset + colon + 1);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        port = *parsed;
    }
    if (auto address = parse_endpoint(host)) {
        address->port = port;
        return format_endpoint(*address);
    }
    // curl 也识别 0x7f000001、0x7f.1 等旧式 inet_aton 格式；
    // 必须拒绝这些含糊输入，避免已验证的主机名被静默改写为 IP。
    if (ambiguous_numeric_host(host)) {
        return std::unexpected(invalid_endpoint(offset));
    }
    const auto name = dns::parse_ascii_name(host);
    if (!name || name->labels.empty()) {
        return std::unexpected(invalid_endpoint(offset + (name ? 0 : name.error().offset)));
    }
    if (host.back() == '.') {
        host.remove_suffix(1);
    }
    return lowercase(host) + ":" + std::to_string(port);
}

/// 判断 URL 百分号转义后的字符是否为十六进制数字。
bool is_hex(char value) {
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

/// 将 curl 错误映射为稳定类别，同时保留原始后端错误码。
EncryptedError backend_error(CURLcode code) {
    auto category = EncryptedErrorCode::Backend;
    if (code == CURLE_OPERATION_TIMEDOUT) {
        category = EncryptedErrorCode::TimedOut;
    } else if (code == CURLE_PEER_FAILED_VERIFICATION || code == CURLE_SSL_ISSUER_ERROR ||
               code == CURLE_SSL_CERTPROBLEM) {
        category = EncryptedErrorCode::CertificateVerification;
    } else if (code == CURLE_SSL_CACERT_BADFILE) {
        category = EncryptedErrorCode::InvalidTlsOptions;
    }
    return {category, static_cast<int>(code)};
}

struct CurlRuntime {
    // 函数内静态实例只初始化一次，成功后才在进程退出阶段清理。
    CURLcode status{curl_global_init(CURL_GLOBAL_DEFAULT)};
    /// 仅在全局初始化成功时释放 curl 的全局资源。
    ~CurlRuntime() {
        if (status == CURLE_OK) {
            curl_global_cleanup();
        }
    }
};

using EasyHandle = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>;
using HeaderList = std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)>;

class EasyOptions {
public:
    /// 借用请求句柄，并初始化首个选项错误的记录状态。
    explicit EasyOptions(CURL* handle) : handle_(handle) {}

    /// 设置请求选项，保留首个失败且不让后续设置覆盖它。
    template <typename T>
    void set(CURLoption option, T value) {
        if (status_ == CURLE_OK) {
            status_ = curl_easy_setopt(handle_, option, value);
        }
    }

    /// 返回已经记录的首个选项错误，全部成功时返回 CURLE_OK。
    [[nodiscard]] CURLcode status() const { return status_; }

private:
    CURL* handle_;
    CURLcode status_{CURLE_OK};
};

/// 将剩余毫秒钳制到 curl 使用的 long 范围，避免平台整数截断。
long remaining_ms(const Deadline& deadline) {
    return static_cast<long>(std::min(deadline.remaining().count(),
        static_cast<std::chrono::milliseconds::rep>((std::numeric_limits<long>::max)())));
}

/// 在 curl 进度回调中检查原截止时间，到期时中止传输。
int check_progress(void* context, curl_off_t, curl_off_t, curl_off_t, curl_off_t) noexcept {
    return static_cast<const Deadline*>(context)->expired() ? 1 : 0;
}

struct BodyBuffer {
    Packet bytes;
    bool oversized{};
    bool allocation_failed{};
};

/// 累积受长度上限约束的 HTTPS 正文，截断或分配失败时中止回调。
std::size_t receive_body(char* data, std::size_t size, std::size_t count,
                         void* context) noexcept {
    auto& body = *static_cast<BodyBuffer*>(context);
    // 先用除法比较剩余空间，同时避免 size 与 count 相乘溢出。
    if (size != 0 && count > (maximum_message - body.bytes.size()) / size) {
        body.oversized = true;
        return 0;
    }
    const auto length = size * count;
    try {
        const auto* begin = reinterpret_cast<const std::byte*>(data);
        body.bytes.insert(body.bytes.end(), begin, begin + length);
    } catch (...) {
        // C 回调边界不能传播 C++ 异常，保存原因后让 curl 停止传输。
        body.allocation_failed = true;
        return 0;
    }
    return length;
}

/// 忽略媒体类型大小写与参数，检查响应是否为 DNS 消息正文。
bool valid_content_type(const char* type) {
    if (type == nullptr) {
        return false;
    }
    std::string_view value{type};
    value = value.substr(0, value.find(';'));
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return lowercase(value) == "application/dns-message";
}

/// 等待 curl 借出的套接字就绪，平台重试始终沿用同一截止时间。
std::expected<void, EncryptedError>
wait_tls_socket(curl_socket_t socket, bool reading, const Deadline& deadline) {
    for (;;) {
        if (deadline.expired()) {
            return std::unexpected(timeout());
        }
        const auto milliseconds = static_cast<int>(std::min(deadline.remaining().count(),
            static_cast<std::chrono::milliseconds::rep>((std::numeric_limits<int>::max)())));
        if (milliseconds == 0) {
            return std::unexpected(timeout());
        }
#if defined(_WIN32)
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(socket, &ready);
        timeval duration{};
        duration.tv_sec = milliseconds / 1000;
        duration.tv_usec = (milliseconds % 1000) * 1000;
        const int result = ::select(0, reading ? &ready : nullptr,
            reading ? nullptr : &ready, nullptr, &duration);
#else
        pollfd descriptor{socket, static_cast<short>(reading ? POLLIN : POLLOUT), 0};
        const int result = ::poll(&descriptor, 1, milliseconds);
#endif
        const int error = result < 0 ? detail::last_error() : 0;
        if (deadline.expired()) {
            return std::unexpected(timeout());
        }
        if (result < 0) {
            if (detail::interrupted(error)) {
                continue;
            }
            return std::unexpected(backend_error(reading ? CURLE_RECV_ERROR : CURLE_SEND_ERROR));
        }
        if (result == 0) {
            continue;
        }
#if !defined(_WIN32)
        if ((descriptor.revents & POLLNVAL) != 0) {
            return std::unexpected(backend_error(reading ? CURLE_RECV_ERROR : CURLE_SEND_ERROR));
        }
        if ((descriptor.revents & (descriptor.events | POLLERR | POLLHUP)) == 0) {
            continue;
        }
#endif
        return {};
    }
}

/// 使用 curl 的 TLS 写接口发送全部字节，仅在暂不可写时等待。
std::expected<void, EncryptedError>
send_tls(CURL* handle, curl_socket_t socket, std::span<const std::byte> bytes,
          const Deadline& deadline) {
    while (!bytes.empty()) {
        if (deadline.expired()) {
            return std::unexpected(timeout());
        }
        std::size_t count{};
        const auto status = curl_easy_send(handle, bytes.data(), bytes.size(), &count);
        if (deadline.expired()) {
            return std::unexpected(timeout());
        }
        if (status == CURLE_AGAIN) {
            const auto ready = wait_tls_socket(socket, false, deadline);
            if (!ready) {
                return std::unexpected(ready.error());
            }
        } else if (status != CURLE_OK) {
            return std::unexpected(backend_error(status));
        } else if (count == 0) {
            return std::unexpected(EncryptedError{EncryptedErrorCode::ConnectionClosed});
        } else {
            bytes = bytes.subspan(count);
        }
    }
    return {};
}

/// 使用 curl 的 TLS 读接口填满缓冲区，提前关闭或到期均返回失败。
std::expected<void, EncryptedError>
receive_tls(CURL* handle, curl_socket_t socket, std::span<std::byte> bytes,
             const Deadline& deadline) {
    while (!bytes.empty()) {
        if (deadline.expired()) {
            return std::unexpected(timeout());
        }
        std::size_t count{};
        // 先读取 TLS 库内部缓存；即使套接字当前不可读，curl 也可能已有解密数据。
        const auto status = curl_easy_recv(handle, bytes.data(), bytes.size(), &count);
        if (deadline.expired()) {
            return std::unexpected(timeout());
        }
        if (status == CURLE_AGAIN) {
            const auto ready = wait_tls_socket(socket, true, deadline);
            if (!ready) {
                return std::unexpected(ready.error());
            }
        } else if (status != CURLE_OK) {
            return std::unexpected(backend_error(status));
        } else if (count == 0) {
            return std::unexpected(EncryptedError{EncryptedErrorCode::ConnectionClosed});
        } else {
            bytes = bytes.subspan(count);
        }
    }
    return {};
}

/// 在 Linux 运行环境寻找系统 CA 文件，Windows 留给系统证书库处理。
std::optional<std::string> system_ca_file() {
#if !defined(_WIN32)
    for (const char* path : {"/etc/ssl/certs/ca-certificates.crt",
                             "/etc/pki/tls/certs/ca-bundle.crt",
                             "/etc/ssl/cert.pem"}) {
        std::error_code error;
        if (std::filesystem::is_regular_file(path, error)) {
            return std::string{path};
        }
    }
#endif
    return std::nullopt;
}

} // 命名空间

/// 在联网前检查显式 CA 文件的路径、可读性和 PEM 证书边界。
std::expected<void, EncryptedError> validate_tls_options(const TlsOptions& tls) {
    if (tls.ca_file.empty()) {
        return {};
    }
    /// 为各种 CA 文件预检失败生成统一的参数错误。
    const auto invalid = [] {
        return std::unexpected(EncryptedError{EncryptedErrorCode::InvalidTlsOptions});
    };
    if (tls.ca_file.find('\0') != std::string::npos) {
        return invalid();
    }
    std::error_code error;
    std::filesystem::path path;
    try {
        path = std::filesystem::path{std::u8string{tls.ca_file.begin(), tls.ca_file.end()}};
    } catch (const std::filesystem::filesystem_error&) {
        return invalid();
    }
    if (!std::filesystem::is_regular_file(path, error)) {
        return invalid();
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return invalid();
    }
    const std::string contents{std::istreambuf_iterator<char>{file}, {}};
    if (file.bad() || contents.empty() || contents.find('\0') != std::string::npos) {
        return invalid();
    }
    constexpr std::string_view begin = "-----BEGIN CERTIFICATE-----";
    constexpr std::string_view end = "-----END CERTIFICATE-----";
    const auto start = contents.find(begin);
    if (start == std::string::npos || contents.find(end, start + begin.size()) == std::string::npos) {
        return invalid();
    }
    return {};
}

/// 解析 HTTPS 地址，规范化主机和端口，并验证路径中的百分号转义。
std::expected<EncryptedEndpoint, EncryptedError> parse_doh_endpoint(std::string_view input) {
    const auto characters = validate_characters(input);
    if (!characters) {
        return std::unexpected(characters.error());
    }
    if (input.size() < 8 || lowercase(input.substr(0, 8)) != "https://") {
        return std::unexpected(invalid_endpoint());
    }
    const auto end = input.find_first_of("/?", 8);
    const auto host_end = end == std::string_view::npos ? input.size() : end;
    const auto authority = parse_authority(input.substr(8, host_end - 8), 443, 8, false);
    if (!authority) {
        return std::unexpected(authority.error());
    }
    for (std::size_t index = host_end; index < input.size(); ++index) {
        if (input[index] == '%') {
            if (input.size() - index < 3 || !is_hex(input[index + 1]) || !is_hex(input[index + 2])) {
                return std::unexpected(invalid_endpoint(index));
            }
            index += 2;
        }
    }
    std::string suffix{input.substr(host_end)};
    if (suffix.empty() || suffix.front() == '?') {
        suffix.insert(suffix.begin(), '/');
    }
    return EncryptedEndpoint{EncryptedTransport::Doh, "https://" + *authority + suffix};
}

/// 解析 DoT 主机地址，将未指定的端口规范为 853。
std::expected<EncryptedEndpoint, EncryptedError> parse_dot_endpoint(std::string_view input) {
    const auto characters = validate_characters(input);
    if (!characters) {
        return std::unexpected(characters.error());
    }
    const auto authority = parse_authority(input, 853, 0, true);
    if (!authority) {
        return std::unexpected(authority.error());
    }
    return EncryptedEndpoint{EncryptedTransport::Dot, *authority};
}

/// 校验公开输入并配置严格 TLS 验证，随后按选定传输完成一次加密交换。
std::expected<Packet, EncryptedError>
exchange_encrypted(const EncryptedEndpoint& endpoint, std::span<const std::byte> query,
                   const Deadline& deadline, const TlsOptions& tls) {
    std::expected<EncryptedEndpoint, EncryptedError> parsed = std::unexpected(invalid_endpoint());
    switch (endpoint.transport) {
    case EncryptedTransport::Doh: parsed = parse_doh_endpoint(endpoint.address); break;
    case EncryptedTransport::Dot: parsed = parse_dot_endpoint(endpoint.address); break;
    default: break;
    }
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (query.size() < minimum_message || query.size() > maximum_message) {
        return std::unexpected(EncryptedError{EncryptedErrorCode::InvalidMessageLength});
    }
    const auto validated = validate_tls_options(tls);
    if (!validated) {
        return std::unexpected(validated.error());
    }
    if (deadline.expired()) {
        return std::unexpected(timeout());
    }
    static CurlRuntime runtime;
    if (runtime.status != CURLE_OK) {
        return std::unexpected(backend_error(runtime.status));
    }
    const auto* version = curl_version_info(CURLVERSION_NOW);
    if (!version || !version->ares || (version->features & CURL_VERSION_SSL) == 0 ||
        (version->features & CURL_VERSION_ASYNCHDNS) == 0 ||
        (endpoint.transport == EncryptedTransport::Doh &&
         (version->features & CURL_VERSION_HTTP2) == 0)) {
        return std::unexpected(EncryptedError{EncryptedErrorCode::BackendUnavailable});
    }
    // 逆序析构使请求句柄先清理，回调状态和请求头在清理期间仍然有效。
    BodyBuffer body;
    HeaderList headers{nullptr, curl_slist_free_all};
    EasyHandle handle{curl_easy_init(), curl_easy_cleanup};
    if (!handle) {
        return std::unexpected(backend_error(CURLE_OUT_OF_MEMORY));
    }
    const bool doh = endpoint.transport == EncryptedTransport::Doh;
    const std::string url = doh ? parsed->address : "https://" + parsed->address + "/";
    auto ca_file = tls.ca_file.empty() ? system_ca_file() : std::optional{tls.ca_file};
#if !defined(_WIN32)
    if (!ca_file) {
        return std::unexpected(EncryptedError{EncryptedErrorCode::BackendUnavailable,
                                             static_cast<int>(CURLE_SSL_CACERT_BADFILE)});
    }
#endif
    EasyOptions options{handle.get()};
    options.set(CURLOPT_URL, url.c_str());
    options.set(CURLOPT_PROTOCOLS_STR, "https");
    options.set(CURLOPT_PROXY, "");
    options.set(CURLOPT_FOLLOWLOCATION, 0L);
    options.set(CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED));
    options.set(CURLOPT_NOSIGNAL, 1L);
    options.set(CURLOPT_SSL_VERIFYPEER, 1L);
    options.set(CURLOPT_SSL_VERIFYHOST, 2L);
    options.set(CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
    options.set(CURLOPT_SSL_OPTIONS, 0L);
    options.set(CURLOPT_CAINFO, ca_file ? ca_file->c_str() : static_cast<const char*>(nullptr));
#if !defined(_WIN32)
    // Schannel 不支持 CAPATH，传入 nullptr 也会失败；Linux 则需清除构建时目录，
    // 确保只使用当前运行环境发现或用户指定的 CA 文件。
    options.set(CURLOPT_CAPATH, static_cast<const char*>(nullptr));
#endif
    options.set(CURLOPT_NOPROGRESS, 0L);
    options.set(CURLOPT_XFERINFOFUNCTION, &check_progress);
    options.set(CURLOPT_XFERINFODATA, &deadline);
    options.set(CURLOPT_FRESH_CONNECT, 1L);

    if (doh) {
        curl_slist* list = nullptr;
        for (const char* value : {"Content-Type: application/dns-message",
                                  "Accept: application/dns-message", "Expect:"}) {
            auto* appended = curl_slist_append(list, value);
            if (!appended) {
                curl_slist_free_all(list);
                return std::unexpected(backend_error(CURLE_OUT_OF_MEMORY));
            }
            list = appended;
        }
        headers.reset(list);
        options.set(CURLOPT_HTTPHEADER, headers.get());
        options.set(CURLOPT_POST, 1L);
        options.set(CURLOPT_POSTFIELDS, reinterpret_cast<const char*>(query.data()));
        options.set(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(query.size()));
        options.set(CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_2TLS));
        options.set(CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(maximum_message));
        options.set(CURLOPT_WRITEFUNCTION, &receive_body);
        options.set(CURLOPT_WRITEDATA, &body);
    } else {
        options.set(CURLOPT_CONNECT_ONLY, 1L);
        options.set(CURLOPT_SSL_ENABLE_ALPN, 0L);
    }
    if (deadline.expired()) {
        return std::unexpected(timeout());
    }
    // c-ares 保证名称解析异步执行；curl 定时器与回调都使用原预算剩余量，
    // 不为解析、握手或收发阶段重新分配完整超时。
    const auto budget = remaining_ms(deadline);
    if (budget == 0) {
        return std::unexpected(timeout());
    }
    options.set(CURLOPT_TIMEOUT_MS, budget);
    options.set(CURLOPT_CONNECTTIMEOUT_MS, budget);
    if (options.status() != CURLE_OK) {
        return std::unexpected(backend_error(options.status()));
    }
    const auto performed = curl_easy_perform(handle.get());
    if (deadline.expired()) {
        return std::unexpected(timeout());
    }
    if (body.oversized || performed == CURLE_FILESIZE_EXCEEDED) {
        return std::unexpected(EncryptedError{EncryptedErrorCode::InvalidMessageLength});
    }
    if (body.allocation_failed) {
        return std::unexpected(backend_error(CURLE_OUT_OF_MEMORY));
    }
    if (performed != CURLE_OK) {
        return std::unexpected(backend_error(performed));
    }
    if (doh) {
        long status{};
        auto info = curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &status);
        if (info != CURLE_OK) {
            return std::unexpected(backend_error(info));
        }
        if (status != 200) {
            return std::unexpected(EncryptedError{EncryptedErrorCode::HttpStatus, 0, status});
        }
        char* content_type = nullptr;
        info = curl_easy_getinfo(handle.get(), CURLINFO_CONTENT_TYPE, &content_type);
        if (info != CURLE_OK) {
            return std::unexpected(backend_error(info));
        }
        if (!valid_content_type(content_type)) {
            return std::unexpected(EncryptedError{EncryptedErrorCode::InvalidContentType, 0, status});
        }
        if (body.bytes.size() < minimum_message) {
            return std::unexpected(EncryptedError{EncryptedErrorCode::InvalidMessageLength});
        }
        if (deadline.expired()) {
            return std::unexpected(timeout());
        }
        return std::move(body.bytes);
    }

    curl_socket_t socket = CURL_SOCKET_BAD;
    const auto info = curl_easy_getinfo(handle.get(), CURLINFO_ACTIVESOCKET, &socket);
    if (info != CURLE_OK || socket == CURL_SOCKET_BAD) {
        return std::unexpected(backend_error(info == CURLE_OK ? CURLE_COULDNT_CONNECT : info));
    }
    Packet framed;
    framed.reserve(query.size() + 2);
    framed.push_back(static_cast<std::byte>(query.size() >> 8U));
    framed.push_back(static_cast<std::byte>(query.size() & 0xffU));
    framed.insert(framed.end(), query.begin(), query.end());
    const auto sent = send_tls(handle.get(), socket, framed, deadline);
    if (!sent) {
        return std::unexpected(sent.error());
    }
    std::array<std::byte, 2> prefix{};
    const auto prefixed = receive_tls(handle.get(), socket, prefix, deadline);
    if (!prefixed) {
        return std::unexpected(prefixed.error());
    }
    const auto length = (std::to_integer<std::size_t>(prefix[0]) << 8U) |
                        std::to_integer<std::size_t>(prefix[1]);
    if (length < minimum_message) {
        return std::unexpected(EncryptedError{EncryptedErrorCode::InvalidMessageLength});
    }
    Packet response(length);
    const auto received = receive_tls(handle.get(), socket, response, deadline);
    if (!received) {
        return std::unexpected(received.error());
    }
    return response;
}

} // 命名空间 dnslab::net
