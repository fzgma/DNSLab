# 命令行接口

本文是 DNSLab 首版命令、选项和退出码的唯一规范，设计已经确认。

**实现状态：** 已接入 `query`、UDP/TCP/自动回退、DoH、DoT、帮助与版本选项。`compare`、`--output`、`--force` 仍是后续设计，不接受这些尚未实现的调用。

## 命令

```text
dnslab query <name> --server <endpoint> [options]
dnslab query <name> --doh <HTTPS URL> [options]
dnslab query <name> --dot <host[:port]> [options]
dnslab compare <name> --server <endpoint> --server <endpoint> [options]
```

- `query`：恰好一个查询名称，且 `--server`、`--doh`、`--dot` 三者恰好选一个，执行一次查询。
- `compare`（待实现）：恰好一个查询名称、至少两个不同 IP 端点，每个端点执行一次查询。
- 查询名称是域名或根名，不是 URL；普通服务器接受 IP 端点，加密服务器允许主机名。详细输入规则见[输入校验](validation.md)。
- 不提供 `-q`、`-c` 子命令别名。

## 选项

| 长选项 | 短选项 | 约定 |
| --- | --- | --- |
| `--server <endpoint>` | `-s` | 普通 DNS 的 IP 端点；与 `--doh`、`--dot` 互斥 |
| `--doh <HTTPS URL>` | 无 | 通过指定 HTTPS 地址查询；不能与 `--transport` 同用 |
| `--dot <host[:port]>` | 无 | 通过指定 TLS 服务器查询，省略端口时为 853；不能与 `--transport` 同用 |
| `--ca-file <path>` | 无 | 仅用于 DoH/DoT，指定可读的 PEM CA 文件；仍检查证书链与服务器身份 |
| `--type A\|AAAA` | `-t` | 默认 `A`；类型值大小写不敏感 |
| `--transport auto\|udp\|tcp` | `-T` | 仅配合 `--server`，默认 `auto`；传输行为见下文 |
| `--timeout-ms <n>` | 无 | 每台服务器的查询总预算，默认 1500 ms；整数范围 100–30000，含边界 |
| `--output <path>`（待实现） | `-o` | 写 JSON 报告，同时保留终端结果；默认不覆盖已有文件 |
| `--force`（待实现） | `-f` | 允许覆盖报告文件，必须与 `--output` 一起使用 |
| `--help` | `-h` | 显示当前命令帮助，成功退出 |
| `--version` | `-V` | 在顶层显示程序版本，成功退出 |

长选项必须带 `--`，短选项必须带 `-`，且区分大小写：`-t` 是记录类型，`-T` 是传输方式。裸 `server` 等单词不作为选项名。

`query` 的所有带值选项均为单值，重复指定报错，包括重复相同值和混用长短形式。未知选项、选项缺值、名称缺失或多余、无效值均属于参数错误；输入验证在网络请求前完成。

首版不提供 `--rounds`、`--concurrency`、`--format`、独立的 `--port` 或 EDNS 参数。

## 服务器端点

地址格式、端口、规范化与重复端点处理统一见[服务器地址](validation.md#服务器地址)。`query` 和 `compare` 的端点数量要求见本页命令定义。

## 传输与超时

- `udp`：只执行 UDP 查询，保留响应中的截断状态。
- `tcp`：直接通过 TCP 查询。
- `auto`：先 UDP，仅收到匹配本次请求的有效 TC 响应时回退到 TCP；UDP 超时不触发回退。
- `--doh`：发送 HTTPS POST，正文为 DNS 报文；不自动跟随重定向。
- `--dot`：建立 TLS 连接，再发送带两字节长度前缀的 DNS 报文。

DoH/DoT 默认严格校验证书链、有效期与主机名或 IP，最低 TLS 1.2；失败不切换到明文传输，也不提供跳过校验选项。Windows 使用系统信任库，Linux 使用运行环境的 CA 文件；私有证书可用 `--ca-file` 指定 CA。加密查询不使用代理环境变量。服务器为主机名时，需要先解析该服务器名称，这一步不保证使用加密 DNS。

`--timeout-ms` 从每台服务器开始查询时计时，覆盖 UDP 收发、TCP 连接与收发、UDP→TCP 回退，以及加密服务器名称解析、TLS 握手和消息交换。回退使用剩余预算，部分发送、部分读取和收到不匹配响应都不能重新获得完整预算。

每个端点有独立预算。整个 `compare` 不受单台预算限制，顺序查询时总耗时可以超过 `--timeout-ms`；实现可顺序或并发执行。一台服务器失败不取消其他服务器的查询。

## 帮助与版本

不带参数运行时显示顶层简要帮助并成功退出。顶层与 `query --help` 分别显示对应范围的帮助；帮助路径不要求提供名称或服务器，也不发起网络请求。`-h` 与 `--help` 等价。

顶层 `--version` 与 `-V` 输出 `DNSLab 0.1.0` 并成功退出。`compare --help` 随比较命令后续实现。

## 输出与退出码

当前查询输出终端结果，包含目标、传输、耗时、响应码、问题、各 section 的记录和尝试过程。以下报告规则为后续设计：查询和比较都输出终端结果；指定 `--output` 时，同时写入本次完整 JSON 报告，结构见[首版交付要求](mvp.md)。

已有输出文件默认拒绝覆盖。只有同时指定 `--output` 和 `--force` 时才允许覆盖；单独使用 `--force` 是参数错误。写入失败必须反馈错误，不能将失败报告为保存成功。

| 退出码 | 含义 |
| ---: | --- |
| `0` | 全部服务器返回可解析且匹配请求的 DNS 响应；RCODE 可以不是 NOERROR。帮助与版本也返回此值 |
| `1` | 至少一项查询超时、网络失败或响应无效；仍尽可能保留完整结果 |
| `2` | 命令行参数或输入无效 |
| `3` | 报告输出失败或内部错误 |

参数错误必须在网络请求前返回。比较中出现查询失败时返回 `1`，其余结果仍然保留；若同时发生报告输出失败，最终返回 `3`。有效的 NXDOMAIN、SERVFAIL、REFUSED 不单独导致非零退出码。

查询已经采用上述退出码；报告相关行为随报告功能实现。

## 示例

当前可运行的查询示例：

```text
dnslab query example.com --server 1.1.1.1 --type A
dnslab query example.com -s 1.1.1.1 -t A
dnslab query example.com -s "[2606:4700:4700::1111]:53" -t AAAA
dnslab query example.com -s 1.1.1.1 -T tcp
dnslab query example.com --doh https://cloudflare-dns.com/dns-query
dnslab query example.com --dot dns.google -t AAAA
dnslab query example.com --dot resolver.example:8853 --ca-file private-ca.pem
```

比较与报告的待实现示例：`dnslab compare example.com -s 1.1.1.1 -s 8.8.8.8 -o report.json`。

当前实现状态见[文档导航](index.md)，完整首版验收见 [MVP](mvp.md)。
