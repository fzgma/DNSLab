#include "dnslab/version.hpp"

#include <CLI/CLI.hpp>

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    CLI::App app{"DNSLab: DNS diagnostic tool (bootstrap; network queries are not yet implemented).", "dnslab"};
    app.set_version_flag("--version", "DNSLab " + std::string{dnslab::version});

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& error) {
        return app.exit(error);
    }

    if (argc == 1) {
        std::cout << app.help();
    }

    return 0;
}
