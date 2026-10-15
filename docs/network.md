# 网络传输

本文定义已实现的端点模型、套接字所有权、查询预算和 UDP/TCP 收发。输入规则见 [validation.md](validation.md)，响应匹配与单服务器查询、自动回退用例见 [architecture.md](architecture.md)。

所有接口位于 `dnslab::net`，核心层不打印提示，也不将网络错误解释为 DNS 响应码。

## 端点模型

`src/net/endpoint.hpp` 定义 `Endpoint`，保存地址与端口。`IpAddress` 是 IPv4 四字节数组与 IPv6 十六字节数组的组合类型，地址按网络字节序保存；`family()` 返回 `IpFamily::V4` 或 `IpFamily::V6`，相等判断覆盖地址族、全部地址字节和端口。

| 接口 | 用途 |
| --- | --- |
| `parse_endpoint(input)` | 校验一个字面地址，返回端点或带位置的输入错误 |
| `format_endpoint(endpoint)` | 输出稳定、带端口的规范形式 |
| `parse_unique_endpoints(inputs)` | 按顺序校验全部端点，遇到重复或非法输入返回其索引 |

IPv4 按四段十进制转换，IPv6 使用系统 `inet_pton`；两者均不调用主机名解析、不创建套接字、不检测连通性。Windows 的这个转换接口不要求初始化 Winsock，参见 [Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-inet_pton)。格式化和相等判断基于解析后的字节，不依赖各平台的地址显示习惯。

## 套接字所有权

`src/net/socket.hpp` 的 `Socket::open(family, transport)` 创建 IPv4/IPv6 的 UDP 或 TCP 套接字，返回 `std::expected<Socket, NetworkError>`。`SocketTransport` 只包含 `Udp`、`Tcp`；非法枚举值返回创建错误，不默认替换。

- 默认构造的 `Socket` 无效；创建成功后立即具备非阻塞属性。Windows 禁止子进程继承句柄，Linux 设置执行新程序时关闭描述符。
- `Socket` 不可复制，可以无异常移动。移动后的源对象无效；移动赋值先释放目标已有资源，自移动不改变状态。
- 析构和 `close()` 释放资源。`close()` 可重复调用，关闭后对象无效。
- `valid()` 检查是否持有句柄；`native_handle()` 只借出句柄，所有权仍属于 `Socket`。调用方不能自行关闭它，也不能延长它的寿命。
- 不提供脱离所有权管理的接管、放弃接口；公共头不引入 Windows 系统头。

Windows 每个成功创建的对象持有一份 Winsock 初始化引用，关闭套接字后释放该引用。移动同时转移句柄与初始化引用；初始化、创建或配置失败时完整清理已取得资源。`WSAStartup` 的错误直接来自返回值，参见 [Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsastartup)。

Windows 通过 [WSASocketW](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw) 的禁止继承标志创建套接字，再设置非阻塞。Linux 在 [socket](https://man7.org/linux/man-pages/man2/socket.2.html) 创建时同时设置 `SOCK_NONBLOCK`、`SOCK_CLOEXEC`；后者在 `exec` 时关闭描述符，并不阻止 `fork` 复制它。关闭时不重试已经交还的描述符。

### 网络错误

`src/net/errors.hpp` 定义 `NetworkError`，保存 `operation`、原生 `system_code` 与错误分类 `code`，不分配动态说明文本。`code` 默认为 `System`，原有初始化和创建错误保持此分类。

| 操作阶段 | 含义 |
| --- | --- |
| `Startup` | Windows 网络运行时初始化或版本协商失败 |
| `SocketCreate` | 创建失败，或地址族、传输类型无效 |
| `SetNonBlocking` | 创建后的非阻塞配置失败 |
| `Bind` | 绑定本机地址失败 |
| `LocalEndpoint` | 读取本机地址失败 |
| `WaitRead`、`WaitWrite` | 等待可读、可写失败或预算耗尽 |
| `Send`、`Receive` | 发送、接收数据失败或预算耗尽 |
| `Connect` | TCP 连接或连接结果检查失败、预算耗尽 |

| 错误分类 | 含义 |
| --- | --- |
| `System` | 平台调用失败，保留原生错误码 |
| `TimedOut` | 同一绝对截止时间已经到期 |
| `InvalidArgument` | 参数无效，例如无效套接字、目标端口为零或超长数据 |
| `DatagramTruncated` | 数据报接收不完整，不能把前缀当成完整消息 |
| `IncompleteDatagram` | 未完整发送一个数据报，不能拆成多次发送 |
| `ConnectionClosed` | TCP 在完成所需字节前正常关闭，或发送无法继续 |
| `InvalidMessageLength` | TCP 消息长度不在 12–65535 字节范围内 |

系统调用失败后立即保存错误码，再清理资源，避免清理过程覆盖错误。主动检测到的错误通常使用系统码 0；平台报告的截断可以保留原生码。等待阶段的错误原样传递，不改写成发送或接收阶段；网络错误不能用 DNS RCODE 替代。

## 查询预算

`src/net/deadline.hpp` 的 `Deadline` 使用 `std::chrono::steady_clock` 保存固定的绝对截止时间。构建时检查时钟使用有符号整数计数，且能够精确表示毫秒；换算使用整数运算。

| 接口 | 用途 |
| --- | --- |
| `Deadline(expires_at)` | 从已有绝对时刻构造预算 |
| `Deadline::after(budget, started_at)` | 将一次预算转换为截止时间，起点默认使用当前单调时钟 |
| `expires_at()` | 读取固定截止时间 |
| `expired(now)` | 检查是否已经到期，当前时刻默认读取单调时钟 |
| `remaining(now)` | 读取剩余毫秒，正的不足一毫秒向上取整；到期或过期为零 |

每台服务器在开始查询时只创建一次预算，UDP、TCP 和回退复用同一截止时间。部分收发、无关响应和重新等待只能减少可用时间，不能重新调用 `after` 获得整段预算。不同服务器分别创建预算；对象没有重置或续期接口。系统等待返回后仍需再次检查是否到期，不能将毫秒向上取整解释为延长查询预算。

`after` 对零或负的内部预算使用起始时刻，对无法表示的未来时刻饱和到时钟上限；`remaining` 的极端差值也不会发生有符号溢出，超过毫秒类型表示能力时饱和。用户输入仍必须先通过 `parse_timeout_ms`，范围和错误由 [validation.md](validation.md#超时输入) 定义。

## UDP 与等待

`src/net/udp.hpp` 提供以下接口，调用方持有由 `Socket::open` 创建的套接字；收发接口用于 UDP 套接字。

| 接口 | 用途 |
| --- | --- |
| `bind_socket(socket, endpoint)` | 绑定本机地址，端口 0 表示让系统分配临时端口 |
| `local_endpoint(socket)` | 读取本机实际地址与端口 |
| `wait_socket(socket, interest, deadline)` | 按 `WaitInterest::Read` 或 `Write` 等待可读、可写 |
| `send_datagram(socket, destination, bytes, deadline)` | 发送一个完整数据报，不连接服务器、不拆分消息 |
| `receive_datagram(socket, deadline)` | 返回 `Datagram`，包含完整 `bytes` 与来源 `sender` |

地址与系统套接字地址在实现内部转换，公开头不暴露平台结构。来源端点同时包含地址族、地址字节和端口，是否属于本次请求由应用层判断。

收发先尝试非阻塞调用，需要等待时复用传入的截止时间。被中断、暂时不可读写、系统等待返回或收到无关数据都不能重建预算；操作前后检查到期。系统等待参数按平台可表示范围截断，等待结束后重新读取剩余时间。

零字节数据报是合法的传输结果，但不是完整 DNS 消息。接收容量为 65535 字节；截断必须返回错误，不向调用方提供可被误接受的前缀。发送拒绝超过此上限的数据，平台对实际 UDP 载荷的更小限制仍由系统错误体现。目标端口不能为零；绑定临时本机端口不受此限制。

传输层不重传、不验证 DNS 标志，也不根据 TC 触发 TCP。显式 UDP 查询可返回带 TC 标志的有效消息。

## TCP 与消息边界

`src/net/tcp.hpp` 接收调用方持有的非阻塞 TCP 套接字，复用与 UDP 相同的 `Deadline`。公共接口不暴露平台结构，连接或完整流操作失败后应关闭该套接字，不能把部分进度当作可重试的完整消息。

| 接口 | 用途 |
| --- | --- |
| `connect_socket(socket, destination, deadline)` | 连接目标端点并确认成功，拒绝端口 0 |
| `send_all(socket, bytes, deadline)` | 循环完成全部字节发送 |
| `receive_exact(socket, bytes, deadline)` | 填满调用方提供的缓冲区，提前关闭即失败 |
| `send_tcp_message(socket, bytes, deadline)` | 加两字节大端长度前缀并完整发送一个消息 |
| `receive_tcp_message(socket, deadline)` | 读取长度前缀和恰好一个消息，不消费后续帧 |

连接进行中时等待连接完成，再读取 `SO_ERROR`。Windows 同时检查可写与异常集合，因为失败连接可能只出现在异常集合；Linux 检查连接事件后读取挂起错误。普通读写等待不能代替连接结果验证，参见 [Winsock select](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select) 与 [Linux connect](https://man7.org/linux/man-pages/man2/connect.2.html)。

部分发送、部分读取、系统调用中断与暂时不可读写均继续使用原截止时间，操作前后检查是否到期。流接收返回零表示连接关闭，不能像 UDP 的空数据报一样成功；Linux 发送抑制 `SIGPIPE`，将对端关闭作为错误返回。空流缓冲区仅在套接字有效且预算未到期时成功。

长度前缀不计入消息长度，采用 [RFC 1035 4.2.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.2) 的两字节网络字节序。本项目消息必须至少容纳 12 字节 DNS Header，最多 65535 字节；收发都拒绝其他长度。接收先验证长度，再分配正文缓冲区。前缀或正文到一半关闭、超时，均不会返回部分消息；长度有效并不表示 DNS 内容有效，后续语义校验仍归应用层负责。

## 验证边界

端点测试只进行内存转换；预算测试传入固定时刻，不使用真实休眠。套接字测试只创建本机资源，并使用回环地址验证非阻塞状态，不联系公共 DNS。创建、移动、关闭和析构必须同时验证资源仍归唯一对象所有。

UDP 测试使用 IPv4/IPv6 回环地址和临时端口，验证地址转换、来源、字节保留、空数据报与截止时间。TCP 测试验证连接、部分收发、消息边界、提前关闭与预算；查询集成测试使用本地模拟服务器验证响应匹配、错误恢复与自动回退。平台实测结果与测试数量统一记录在 [todo.md](todo.md)。
