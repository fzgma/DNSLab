#include "dnslab/version.hpp"

#include "app/encrypted_query.hpp"
#include "app/query.hpp"
#include "cli/output.hpp"
#include "dns/name_codec.hpp"
#include "net/deadline.hpp"
#include "net/encrypted_transport.hpp"
#include "net/endpoint.hpp"

#include <CLI/CLI.hpp>

#include <exception>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace {

int argument_error(std::string_view message) {
    std::cerr << "Argument error: " << message << '\n';
    return 2;
}

CLI::Option* single_value(CLI::Option* option) {
    return option->expected(1)->multi_option_policy(CLI::MultiOptionPolicy::Throw);
}

std::string ascii_upper(std::string text) {
    for (auto& byte : text) {
        if (byte >= 'a' && byte <= 'z') {
            byte = static_cast<char>(byte - 'a' + 'A');
        }
    }
    return text;
}

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

int run(int argc, char* argv[]) {
    using namespace dnslab;
    CLI::App command{"DNSLab: DNS diagnostic tool.", "dnslab"};
    command.set_version_flag("-V,--version", "DNSLab " + std::string{version});
    command.require_subcommand(0, 1);

    auto* query = command.add_subcommand("query", "Query one DNS server using UDP, TCP, HTTPS or TLS");
    std::string name;
    std::string server_text;
    std::string doh_text;
    std::string dot_text;
    std::string type_text{"A"};
    std::string transport_text{"auto"};
    std::string timeout_text{"1500"};
    std::string ca_file;

    single_value(query->add_option("name", name, "DNS name or '.' for the root"))->required();
    auto* server_option = single_value(query->add_option(
        "-s,--server", server_text, "Plain DNS IP endpoint (default port 53)"))->type_name("ENDPOINT");
    auto* doh_option = single_value(query->add_option(
        "--doh", doh_text, "DNS over HTTPS URL"))->type_name("HTTPS_URL");
    auto* dot_option = single_value(query->add_option(
        "--dot", dot_text, "DNS over TLS host or IP (default port 853)"))->type_name("HOST[:PORT]");
    single_value(query->add_option("-t,--type", type_text, "Record type (case-insensitive)"))
        ->type_name("A|AAAA")->default_str("A");
    auto* transport_option = single_value(query->add_option(
        "-T,--transport", transport_text, "Plain DNS transport; only valid with --server"))
        ->type_name("auto|udp|tcp")->default_str("auto");
    single_value(query->add_option("--timeout-ms", timeout_text, "Total query budget in milliseconds"))
        ->type_name("100..30000")->default_str("1500");
    auto* ca_option = single_value(query->add_option(
        "--ca-file", ca_file, "PEM CA file for --doh or --dot; default: system trust"))->type_name("PEM");

    try {
        command.parse(argc, argv);
    } catch (const CLI::ParseError& error) {
        if (error.get_exit_code() == 0) {
            return command.exit(error);
        }
        std::cerr << "Argument error: ";
        command.exit(error);
        return 2;
    }
    if (!query->parsed()) {
        std::cout << command.help();
        return 0;
    }

    const auto targets = server_option->count() + doh_option->count() + dot_option->count();
    if (targets != 1) {
        return argument_error("query requires exactly one of --server, --doh or --dot.");
    }
    const bool encrypted = server_option->count() == 0;
    if (encrypted && transport_option->count() != 0) {
        return argument_error("--transport is only valid with --server.");
    }
    if (!encrypted && ca_option->count() != 0) {
        return argument_error("--ca-file is only valid with --doh or --dot.");
    }
    if (ca_option->count() != 0 && ca_file.empty()) {
        return argument_error("--ca-file must name a readable PEM file.");
    }

    type_text = ascii_upper(std::move(type_text));
    if (type_text != "A" && type_text != "AAAA") {
        return argument_error("--type must be A or AAAA.");
    }
    app::TransportMode mode;
    if (transport_text == "auto") {
        mode = app::TransportMode::Auto;
    } else if (transport_text == "udp") {
        mode = app::TransportMode::Udp;
    } else if (transport_text == "tcp") {
        mode = app::TransportMode::Tcp;
    } else {
        return argument_error("--transport must be auto, udp or tcp.");
    }
    const auto budget = net::parse_timeout_ms(timeout_text);
    if (!budget) {
        return argument_error("--timeout-ms must contain digits only, with a value from 100 to 30000.");
    }
    auto parsed_name = dns::parse_ascii_name(name);
    if (!parsed_name) {
        return argument_error("Invalid DNS query name at byte " +
                              std::to_string(parsed_name.error().offset) + ".");
    }
    const dns::DnsQuestion question{
        std::move(*parsed_name), static_cast<std::uint16_t>(type_text == "A" ? 1 : 28), 1};

    if (!encrypted) {
        const auto server = net::parse_endpoint(server_text);
        if (!server) {
            return argument_error("Invalid IP endpoint at byte " +
                                  std::to_string(server.error().offset) + ".");
        }
        const auto result = app::query_server(question, *server, mode, *budget);
        if (!result) {
            cli::print_error(std::cout, std::cerr, net::format_endpoint(*server),
                             transport_text, question, result.error());
            return query_exit_code(result.error());
        }
        cli::print_result(std::cout, *result);
        return 0;
    }

    const bool doh = doh_option->count() != 0;
    const auto server = doh ? net::parse_doh_endpoint(doh_text) : net::parse_dot_endpoint(dot_text);
    if (!server) {
        return argument_error(std::string{doh ? "Invalid HTTPS URL" : "Invalid TLS server"} +
                              " at byte " + std::to_string(server.error().offset) + ".");
    }
    const net::TlsOptions tls{ca_file};
    const auto valid_tls = net::validate_tls_options(tls);
    if (!valid_tls) {
        return argument_error("--ca-file must be a readable, nonempty PEM certificate file.");
    }
    const auto result = app::query_encrypted(question, *server, *budget, tls);
    if (!result) {
        cli::print_error(std::cout, std::cerr, server->address,
                         doh ? "doh" : "dot", question, result.error());
        return query_exit_code(result.error());
    }
    cli::print_result(std::cout, *result);
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        return run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "Internal error: " << error.what() << '\n';
    } catch (...) {
        std::cerr << "Internal error: unknown exception\n";
    }
    return 3;
}
