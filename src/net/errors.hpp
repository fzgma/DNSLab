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
    // Windows 保存 Winsock 错误码，Linux 保存 errno 值。
    int system_code;
    NetworkErrorCode code{NetworkErrorCode::System};
};

} // 命名空间 dnslab::net
