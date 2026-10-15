# 网络基础

本文定义已实现的端点模型、套接字所有权和查询预算。输入规则见 [validation.md](validation.md)，一次查询如何使用这些模块见 [architecture.md](architecture.md)。UDP/TCP 收发、响应匹配和截断回退尚未实现。

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

`src/net/errors.hpp` 定义 `NetworkError`，保存 `operation` 与原生 `system_code`，不分配动态说明文本。

| 操作阶段 | 含义 |
| --- | --- |
| `Startup` | Windows 网络运行时初始化或版本协商失败 |
| `SocketCreate` | 创建失败，或地址族、传输类型无效 |
| `SetNonBlocking` | 创建后的非阻塞配置失败 |

系统调用失败后立即保存错误码，再清理资源，避免清理过程覆盖错误。收发、等待及超时的错误与状态在对应功能接入时扩展；不能用 DNS RCODE 替代。

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

## 验证边界

端点测试只进行内存转换；预算测试传入固定时刻，不使用真实休眠。套接字测试只创建本机资源，并使用回环地址验证非阻塞状态，不联系公共 DNS。创建、移动、关闭和析构必须同时验证资源仍归唯一对象所有。

本地模拟服务器、收发与回退测试留待传输功能实现。平台实测结果与测试数量统一记录在 [todo.md](todo.md)。
