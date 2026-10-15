#pragma once

#include "net/deadline.hpp"
#include "net/endpoint.hpp"
#include "net/errors.hpp"
#include "net/socket.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <vector>

namespace dnslab::net {

enum class WaitInterest { Read, Write };

struct Datagram {
    std::vector<std::byte> bytes;
    Endpoint sender;
};

/// 在原截止时间内等待套接字可读或可写，并传播等待阶段错误。
[[nodiscard]] std::expected<void, NetworkError>
wait_socket(const Socket& socket, WaitInterest interest, const Deadline& deadline);

/// 将套接字绑定到给定本地地址，端口零表示由系统分配临时端口。
[[nodiscard]] std::expected<void, NetworkError>
bind_socket(const Socket& socket, const Endpoint& endpoint);

/// 读取套接字实际绑定的本地地址和端口。
[[nodiscard]] std::expected<Endpoint, NetworkError>
local_endpoint(const Socket& socket);

/// 使用调用方提供的 UDP 套接字发送完整数据报，不拆包也不建立连接。
[[nodiscard]] std::expected<void, NetworkError>
send_datagram(const Socket& socket, const Endpoint& destination,
              std::span<const std::byte> bytes, const Deadline& deadline);

/// 返回完整数据报及来源端点，发生截断时拒绝返回前缀数据。
[[nodiscard]] std::expected<Datagram, NetworkError>
receive_datagram(const Socket& socket, const Deadline& deadline);

} // 命名空间 dnslab::net
