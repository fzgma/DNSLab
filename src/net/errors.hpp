#pragma once

namespace dnslab::net {

enum class NetworkOperation {
    Startup,
    SocketCreate,
    SetNonBlocking,
};

struct NetworkError {
    NetworkOperation operation;
    // Winsock error code on Windows, errno value on Linux.
    int system_code;
};

} // namespace dnslab::net
