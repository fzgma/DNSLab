#pragma once

namespace dnslab::net {

enum class NetworkOperation {
    Startup,
    SocketCreate,
    SetNonBlocking,
    Bind,
    LocalEndpoint,
    WaitRead,
    WaitWrite,
    Send,
    Receive,
    Connect,
};

enum class NetworkErrorCode {
    System,
    TimedOut,
    InvalidArgument,
    DatagramTruncated,
    IncompleteDatagram,
    ConnectionClosed,
    InvalidMessageLength,
};

struct NetworkError {
    NetworkOperation operation;
    // Winsock error code on Windows, errno value on Linux.
    int system_code;
    NetworkErrorCode code{NetworkErrorCode::System};
};

} // namespace dnslab::net
