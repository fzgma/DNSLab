#pragma once

#include "app/encrypted_query.hpp"

#include <iosfwd>
#include <string_view>

namespace dnslab::cli {

void print_result(std::ostream& output, const app::QueryResult& result);
void print_result(std::ostream& output, const app::EncryptedQueryResult& result);

void print_error(std::ostream& output, std::ostream& errors,
                 std::string_view target, std::string_view requested_transport,
                 const dns::DnsQuestion& question, const app::QueryError& error);

} // namespace dnslab::cli
