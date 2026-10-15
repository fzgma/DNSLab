#include "dnslab/version.hpp"

#include "app/encrypted_query.hpp"
#include "app/query.hpp"
#include "cli/output.hpp"
#include "dns/name_codec.hpp"
#include "net/deadline.hpp"
#include "net/encrypted_transport.hpp"
#include "net/endpoint.hpp"

#include <CLI/CLI.hpp>

#include <cstdio>
#include <exception>
#include <format>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>

namespace {

/// 输出中文参数错误并返回约定的参数错误退出码。
int argument_error(std::string_view message) {
    std::println(stderr, "参数错误: {}", message);
    return 2;
}

/// 将带值选项限制为恰好一个值，并拒绝重复指定。
CLI::Option* single_value(CLI::Option* option) {
    return option->expected(1)->multi_option_policy(CLI::MultiOptionPolicy::Throw);
}

/// 仅折叠 ASCII 小写字母，使记录类型不区分大小写。
std::string ascii_upper(std::string text) {
    for (auto& byte : text) {
        if (byte >= 'a' && byte <= 'z') {
            byte = static_cast<char>(byte - 'a' + 'A');
        }
    }
    return text;
}

/// 为第三方解析错误提供稳定的中文原因，不直接暴露其英文提示。
std::string_view parse_error_reason(int code) {
    switch (static_cast<CLI::ExitCodes>(code)) {
    case CLI::ExitCodes::RequiredError: return "缺少必填参数。";
    case CLI::ExitCodes::ArgumentMismatch: return "选项缺少值、值数量不符或重复指定了单值选项。";
    case CLI::ExitCodes::ExtrasError: return "存在未知选项、未知命令或多余参数。";
    case CLI::ExitCodes::ConversionError: return "选项值无法转换为要求的类型。";
    case CLI::ExitCodes::ValidationError: return "选项值不符合要求。";
    case CLI::ExitCodes::RequiresError: return "缺少与当前选项配套的参数。";
    case CLI::ExitCodes::ExcludesError: return "指定了不能同时使用的选项。";
    default: return "命令行参数无法解析。";
    }
}

/// 将查询失败映射为参数、查询或内部错误退出码。
int query_exit_code(const dnslab::app::QueryError& error) {
    using namespace dnslab;
    switch (error.code) {
    case app::QueryErrorCode::InvalidMode:
    case app::QueryErrorCode::InvalidTimeout:
    case app::QueryErrorCode::InvalidEndpoint:
    case app::QueryErrorCode::Encode:
        return 2;
    case app::QueryErrorCode::IdGeneration:
        return 3;
    default:
        break;
    }
    if (const auto* detail = std::get_if<net::EncryptedError>(&error.detail)) {
        if (detail->code == net::EncryptedErrorCode::InvalidEndpoint ||
            detail->code == net::EncryptedErrorCode::InvalidTlsOptions) {
            return 2;
        }
        if (detail->code == net::EncryptedErrorCode::BackendUnavailable) {
            return 3;
        }
    }
    return 1;
}

/// 中文化帮助模板和默认选项说明，并让后续子命令继承相同配置。
void localize_help(CLI::App& command) {
    const auto formatter = command.get_formatter();
    for (const auto& [key, value] : {
             std::pair{"Usage", "用法"}, {"OPTIONS", "选项"}, {"POSITIONALS", "位置参数"},
             {"SUBCOMMAND", "命令"}, {"SUBCOMMANDS", "命令"}, {"REQUIRED", "必填"},
             {"TEXT", "文本"}, {"Env", "环境变量"}, {"Needs", "需要"}, {"Excludes", "互斥"}}) {
        formatter->label(key, value);
    }
    command.option_defaults()->group("选项");
    command.set_help_flag("-h,--help", "显示帮助并退出");
    command.set_version_flag("-V,--version", "DNSLab " + std::string{dnslab::version},
                             "显示程序版本并退出");
}

/// 校验命令行输入后执行一次查询，并用统一格式展示结果。
int run(int argc, char* argv[]) {
    using namespace dnslab;
    CLI::App command{"DNSLab：DNS 查询与诊断工具。", "dnslab"};
    localize_help(command);
    command.require_subcommand(0, 1);

    auto* query = command.add_subcommand("query", "通过 UDP、TCP、HTTPS 或 TLS 查询一个 DNS 服务器");
    query->group("命令");
    // CLI11 在复制选项默认分组前创建继承的帮助项，因此这里重建以应用中文分组。
    query->set_help_flag("-h,--help", "显示帮助并退出");
    std::string name;
    std::string server_text;
    std::string doh_text;
    std::string dot_text;
    std::string type_text{"A"};
    std::string transport_text{"auto"};
    std::string timeout_text{"1500"};
    std::string ca_file;

    single_value(query->add_option("名称", name, "DNS 域名；根名称使用 '.'"))
        ->type_name("域名")->required();
    auto* server_option = single_value(query->add_option(
        "-s,--server", server_text, "普通 DNS 的 IP 地址与可选端口，默认端口为 53"))->type_name("地址");
    auto* doh_option = single_value(query->add_option(
        "--doh", doh_text, "DoH 服务器的 HTTPS 地址"))->type_name("HTTPS地址");
    auto* dot_option = single_value(query->add_option(
        "--dot", dot_text, "DoT 服务器的主机名或 IP，默认端口为 853"))->type_name("主机[:端口]");
    single_value(query->add_option("-t,--type", type_text, "记录类型，不区分大小写"))
        ->type_name("A|AAAA")->default_str("A");
    auto* transport_option = single_value(query->add_option(
        "-T,--transport", transport_text, "普通 DNS 的传输方式，仅与 --server 配合使用"))
        ->type_name("auto|udp|tcp")->default_str("auto");
    single_value(query->add_option("--timeout-ms", timeout_text, "整个查询的超时预算，单位为毫秒"))
        ->type_name("100..30000")->default_str("1500");
    auto* ca_option = single_value(query->add_option(
        "--ca-file", ca_file, "DoH 或 DoT 使用的 PEM CA 文件，默认使用系统信任"))
        ->type_name("PEM文件");

    try {
        // Windows 从宽字符命令行重建 UTF-8 参数，避免中文 CA 路径经过本机代码页后失真。
        command.parse(argc, command.ensure_utf8(argv));
    } catch (const CLI::CallForVersion&) {
        std::println("DNSLab {}", version);
        return 0;
    } catch (const CLI::CallForHelp&) {
        std::print("{}", command.help());
        return 0;
    } catch (const CLI::CallForAllHelp&) {
        std::print("{}", command.help("", CLI::AppFormatMode::All));
        return 0;
    } catch (const CLI::ParseError& error) {
        // 解析器只提供错误类别；提示由应用生成，避免第三方英文泄漏到终端。
        return argument_error(std::format("{}（解析错误码 {}）请使用 --help 或 query --help 查看用法。",
                                           parse_error_reason(error.get_exit_code()),
                                           error.get_exit_code()));
    }
    if (!query->parsed()) {
        std::print("{}", command.help());
        return 0;
    }

    const auto targets = server_option->count() + doh_option->count() + dot_option->count();
    if (targets != 1) {
        return argument_error("query 必须且只能指定 --server、--doh、--dot 中的一项。");
    }
    const bool encrypted = server_option->count() == 0;
    if (encrypted && transport_option->count() != 0) {
        return argument_error("--transport 只能与 --server 配合使用。");
    }
    if (!encrypted && ca_option->count() != 0) {
        return argument_error("--ca-file 只能与 --doh 或 --dot 配合使用。");
    }
    if (ca_option->count() != 0 && ca_file.empty()) {
        return argument_error("--ca-file 必须指定可读的 PEM 文件。");
    }

    type_text = ascii_upper(std::move(type_text));
    if (type_text != "A" && type_text != "AAAA") {
        return argument_error("--type 只能为 A 或 AAAA。");
    }
    app::TransportMode mode;
    if (transport_text == "auto") {
        mode = app::TransportMode::Auto;
    } else if (transport_text == "udp") {
        mode = app::TransportMode::Udp;
    } else if (transport_text == "tcp") {
        mode = app::TransportMode::Tcp;
    } else {
        return argument_error("--transport 只能为 auto、udp 或 tcp。");
    }
    const auto budget = net::parse_timeout_ms(timeout_text);
    if (!budget) {
        return argument_error("--timeout-ms 只能包含十进制数字，取值范围为 100–30000。");
    }
    auto parsed_name = dns::parse_ascii_name(name);
    if (!parsed_name) {
        return argument_error(std::format("DNS 查询名称无效，字节偏移为 {}。",
                                           parsed_name.error().offset));
    }
    const dns::DnsQuestion question{
        std::move(*parsed_name), static_cast<std::uint16_t>(type_text == "A" ? 1 : 28), 1};

    if (!encrypted) {
        const auto server = net::parse_endpoint(server_text);
        if (!server) {
            return argument_error(std::format("IP 服务器地址无效，字节偏移为 {}。",
                                               server.error().offset));
        }
        const auto result = app::query_server(question, *server, mode, *budget);
        if (!result) {
            cli::print_error(stdout, stderr, net::format_endpoint(*server),
                             transport_text, question, result.error());
            return query_exit_code(result.error());
        }
        cli::print_result(stdout, *result);
        return 0;
    }

    const bool doh = doh_option->count() != 0;
    const auto server = doh ? net::parse_doh_endpoint(doh_text) : net::parse_dot_endpoint(dot_text);
    if (!server) {
        return argument_error(std::format("{}无效，字节偏移为 {}。",
                                           doh ? "HTTPS 地址" : "TLS 服务器地址",
                                           server.error().offset));
    }
    const net::TlsOptions tls{ca_file};
    const auto valid_tls = net::validate_tls_options(tls);
    if (!valid_tls) {
        return argument_error("--ca-file 必须是可读、非空且具有证书边界的 PEM 文件。");
    }
    // 加密查询始终交给严格校验证书的用例；失败不能切换到普通 DNS。
    const auto result = app::query_encrypted(question, *server, *budget, tls);
    if (!result) {
        cli::print_error(stdout, stderr, server->address,
                         doh ? "doh" : "dot", question, result.error());
        return query_exit_code(result.error());
    }
    cli::print_result(stdout, *result);
    return 0;
}

/// 尽力输出内部错误，避免错误流失效时再次抛出而中止退出码处理。
void report_internal_error(std::string_view message, int system_code = 0) noexcept {
    try {
        if (system_code != 0) {
            std::println(stderr, "内部错误: {}（错误码 {}）。", message, system_code);
        } else {
            std::println(stderr, "内部错误: {}。", message);
        }
    } catch (...) {
        // 错误流本身可能已关闭；此时保留内部错误退出码，不继续写入同一通道。
    }
}

} // 匿名命名空间

/// 将未处理异常转换为中文诊断和内部错误退出码。
int main(int argc, char* argv[]) {
    try {
        return run(argc, argv);
    } catch (const std::system_error& error) {
        report_internal_error("系统操作异常", error.code().value());
    } catch (const std::exception&) {
        report_internal_error("程序运行异常");
    } catch (...) {
        report_internal_error("未知异常");
    }
    return 3;
}
