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

/// 使用调用方持有的新建非阻塞 TCP 套接字连接目标，并确认连接结果。
// 连接失败或流操作未完成后应丢弃该连接，不能将部分进度当作可重试消息。
[[nodiscard]] std::expected<void, NetworkError>
connect_socket(Socket& socket, const Endpoint& destination, const Deadline& deadline);

/// 在原截止时间内发送全部字节，部分进度不会续期。
// 套接字有效且预算未到期时空缓冲区成功；提前关闭不能视为成功。
[[nodiscard]] std::expected<void, NetworkError>
send_all(Socket& socket, std::span<const std::byte> bytes, const Deadline& deadline);

/// 在原截止时间内填满缓冲区，提前遇到流末尾则返回连接关闭错误。
[[nodiscard]] std::expected<void, NetworkError>
receive_exact(Socket& socket, std::span<std::byte> bytes, const Deadline& deadline);

/// 为 12 至 65535 字节消息添加两字节大端长度前缀并完整发送。
// 帧接口不解释 DNS 字段，接收时也不消费下一帧。
[[nodiscard]] std::expected<void, NetworkError>
send_tcp_message(Socket& socket, std::span<const std::byte> bytes, const Deadline& deadline);

/// 读取并校验长度前缀，再接收恰好一个完整 DNS 长度帧。
[[nodiscard]] std::expected<std::vector<std::byte>, NetworkError>
receive_tcp_message(Socket& socket, const Deadline& deadline);

} // 命名空间 dnslab::net
