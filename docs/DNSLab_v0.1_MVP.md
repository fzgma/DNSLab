# DNSLab v0.1 MVP 需求与实施说明

- **项目版本：** v0.1.0
- **文档版本：** 1.0
- **状态：** 待实现
- **项目类型：** 跨平台 DNS 命令行诊断工具
- **语言标准：** C++23
- **目标平台：** Windows 10/11 x64、Linux x86_64（CI 优先 Ubuntu 22.04+）

## 1. v0.1 的目标

v0.1 只验证 DNSLab 的核心价值：**向用户指定的 DNS 服务器发起真实 DNS 查询，把回答、响应状态与耗时以一致的格式展示，并能比较多个服务器。**

这不是完整 DNS 工具套件。首个版本优先保证协议处理正确、错误可区分、结果可复现、测试不依赖公共 DNS。

## 2. MVP 范围

### 2.1 必须交付（P0）

1. Windows 和 Linux 均可使用 CMake 构建。
2. CLI 支持 `--help` 和 `--version`。
3. 支持查询类型 `A`、`AAAA`。
4. 用户必须显式指定 DNS 服务器 IP 地址；不自动使用系统默认解析器，也不通过 DNS 解析服务器主机名。
5. 支持 DNS over UDP 与 DNS over TCP；默认 `auto`：先 UDP，仅当收到有效且设置了 `TC=1` 的响应时，才通过 TCP 重试。
6. 解析并展示 `NOERROR`、`FORMERR`、`SERVFAIL`、`NXDOMAIN`、`NOTIMP`、`REFUSED` 等 RCODE；未知值显示数字代码。
7. 展示回答中的 A、AAAA、CNAME 记录、TTL、响应耗时、服务器与传输方式。
8. 支持一次性比较两个或更多 DNS 服务器；每个服务器只查询一次，不做重复采样和排名。
9. 终端提供人类可读结果；支持将结果写入 JSON 文件。
10. 对超时、套接字错误、错误响应、畸形或截断报文给出明确状态；单个服务器失败不得中止其他服务器的比较。
11. 包含 DNS 编解码单元测试、本地假 DNS 服务器集成测试、Windows/Linux CI 和最小使用文档。

### 2.2 明确不做（不阻塞 v0.1）

- MX、NS、TXT、SOA、PTR 等查询类型。
- 多轮采样、p50/p95、长期延迟统计、CSV 或 Markdown 报告。
- DoH、DoT、DNSSEC 验证、IDN 自动转换。
- 递归解析器、权威服务器发现、根服务器迭代查询。
- GUI、实时监控、历史数据库、自动更改系统 DNS 设置。
- 自动判断哪个 DNS 服务商“最好”或对不同回答直接判定谁错误。

## 3. CLI 设计

程序名：`dnslab`

### 3.1 单服务器查询

```text
dnslab query example.com --server 1.1.1.1 --type A
```

### 3.2 IPv6 DNS 服务器

```text
dnslab query example.com --server [2606:4700:4700::1111]:53 --type AAAA
```

### 3.3 显式 TCP

```text
dnslab query example.com --server 1.1.1.1 --type A --transport tcp
```

### 3.4 比较多个服务器并导出 JSON

```text
dnslab compare example.com \
  --server 1.1.1.1 \
  --server 8.8.8.8 \
  --type A \
  --timeout-ms 1500 \
  --output report.json
```

### 3.5 参数约定

| 参数 | 规则 |
|---|---|
| `query <name>` | 单服务器查询；必须恰好提供一个 `--server` |
| `compare <name>` | 至少提供两个 `--server`；每台服务器查询一次 |
| `--server <ip[:port]>` | 可重复；仅接受 IPv4/IPv6 字面地址；默认端口 53；IPv6 带端口时使用方括号 |
| `--type A\|AAAA` | 默认 `A`，大小写不敏感 |
| `--transport auto\|udp\|tcp` | 默认 `auto`；`auto` 仅对有效 TC 响应进行 TCP 回退，不因 UDP 超时而自动切换 TCP |
| `--timeout-ms <n>` | 每次操作超时，默认 1500，允许 100–30000 |
| `--output <path>` | 将本次完整结果写入 JSON；默认拒绝覆盖已有文件，`--force` 才覆盖 |
| `--force` | 与 `--output` 一起使用时允许覆盖文件 |
| `--help` | 展示用法 |
| `--version` | 输出版本号并退出 |

v0.1 不提供 `--rounds`、`--concurrency`、`--format`、自定义 EDNS 参数。`compare` 的实现可以并发，也可以顺序执行；若采用并发，必须保证超时和结果归属正确，且每个服务器都有独立结果。

## 4. 输出要求

### 4.1 终端输出示例

以下仅为格式示例，不代表真实查询结果：

```text
DNSLab v0.1.0
Query: example.com.  type=A
Server: 1.1.1.1:53  transport=UDP
Status: DNS response received  rcode=NOERROR  elapsed=18.4 ms

ANSWER
  example.com.  300  A  93.184.216.34

Result: PASS
```

如果收到 `NXDOMAIN`，应明确显示 DNS 服务器已返回有效的 NXDOMAIN 响应，而不是显示为网络故障。如果没有对应类型的直接答案，应输出“NOERROR，但没有该类型的直接回答”，不得直接宣告域名不存在。

### 4.2 JSON 报告

JSON 顶层至少包含：

- `schema_version`
- `tool_version`
- `started_at`（RFC 3339，含时区）
- `duration_ms`
- `query`（name、type）
- `options`（timeout、transport）
- `results`（每台 DNS 服务器一项）

每个 `results[]` 至少包含：

- `server`
- `transport_used`
- `elapsed_ms`（没有有效响应时为 `null`）
- `transport_status`（稳定枚举，例如 `ok`、`timeout`、`connection_refused`、`io_error`、`invalid_response`）
- `rcode`（未收到有效响应时为 `null`）
- `flags`（至少包括 `tc`、`aa`、`ra`、`ad`、`cd`）
- `answers`（记录名称、类型、TTL、可读值；不支持解码的记录应安全保留类型编号和 RDATA 长度）
- `error`（无错误时为 `null`）

`transport_status` 描述传输和报文有效性；`rcode` 描述 DNS 协议响应。两者不得混为一个状态。JSON 字段名与含义一经发布，应保持兼容；后续破坏性变更需要提高 `schema_version`。

## 5. 诊断与状态规则

- **成功收到有效 DNS 响应**：无论 RCODE 是 `NOERROR`、`NXDOMAIN`、`SERVFAIL` 还是 `REFUSED`，均属于传输成功。
- **UDP 超时**：显示超时；不得伪造 RCODE，也不得默认通过 TCP 重试。
- **TCP 失败**：记录连接、发送、读取或超时阶段的具体错误。
- **UDP TC=1**：在 `auto` 模式下以相同问题通过 TCP 重试；报告记录 UDP 截断以及 TCP 最终结果。
- **不同服务器答案不同**：展示差异，不直接判断某个回答错误。缓存、地理调度、策略和传播延迟都可能造成差异。
- **TTL 不同**：作为观察结果展示，不单独判定异常。

## 6. 协议正确性和安全要求

1. 构造符合 DNS 报文格式的查询，事务 ID 为每次请求生成，并校验响应事务 ID、QR 标志和 Question。
2. UDP 响应必须来自本次请求的目标端点；无关或不匹配响应不得被当成成功结果。
3. 域名编码与解码必须做边界检查。压缩指针越界、指针循环、长度不足、计数与实际报文不符等输入必须安全失败，不得崩溃、越界读取或无限循环。
4. TCP DNS 消息使用两字节长度前缀；必须正确处理部分发送、部分读取和消息长度验证。
5. A 记录必须恰好解析为 4 字节 IPv4 地址；AAAA 记录必须恰好解析为 16 字节 IPv6 地址；CNAME 名称使用安全的 DNS 名称解码器。
6. 名称比较遵循 DNS ASCII 大小写不敏感语义；不支持的记录类型可以显示类型编号和 RDATA 长度，不可误解析为已支持的类型。
7. 对用户输入的域名进行长度、标签与字符验证；v0.1 仅承诺 ASCII 域名和用户已转换为 Punycode 的域名，不自动对 Unicode 域名做 IDNA 转换。
8. 不收集遥测、不上传查询结果。文档应提示：查询名称和响应内容会发送到指定 DNS 服务器，TXT 等 DNS 数据可能包含敏感验证内容。

## 7. 技术约束与建议架构

- C++23，CMake；将 CLI、DNS 报文处理、网络传输、结果模型和报告输出分层。
- 不使用现成 DNS 客户端库代替本项目的 DNS 报文构造与解析，以保留协议实现价值。
- 网络层可以使用薄的跨平台套接字适配层；Windows 必须正确初始化/清理 Winsock，Linux 必须正确处理文件描述符和系统错误。
- 不要求异步框架；先采用容易验证的同步超时模型。比较模式可在稳定后并发化。
- 推荐源代码边界：

```text
src/
  cli/          参数解析与命令调度
  dns/          DNS wire format、名称压缩、资源记录解析、RCODE
  net/          UDP/TCP 套接字和超时
  report/       终端与 JSON 输出
  app/          查询用例、比较用例、退出码映射
include/dnslab/ 公共类型（如确有必要）
tests/
  unit/         报文编解码与参数测试
  integration/  本地假 DNS 服务器测试
```

实际目录可以调整，但模块边界和依赖方向应保持清楚。DNS 解析代码不应直接操作终端或文件；报告层不应自行发送网络请求。

## 8. 自动化测试要求

CI 不应依赖 `1.1.1.1`、`8.8.8.8` 等公共 DNS。使用本地假 DNS 服务端模拟以下场景：

1. 正常 A 回答；正常 AAAA 回答。
2. CNAME 回答及其后续回答记录。
3. NXDOMAIN、SERVFAIL、REFUSED。
4. 不返回响应，验证超时。
5. 事务 ID、Question 或来源端点不匹配的响应。
6. 截断 UDP 响应后，TCP 回退成功。
7. TC=1 后 TCP 失败。
8. 畸形报文：短报文、非法压缩指针、指针循环、错误的 RDLENGTH、数量字段不匹配。
9. JSON 输出内容正确；已有报告文件默认不被覆盖。
10. compare 中一台服务器失败时，其余服务器仍产生结果。

除协议测试外，必须测试非法参数、无效 IP、无效端口、未知记录类型、超出范围的超时值，以及 Windows/Linux 的编译。

## 9. 退出码

| 代码 | 含义 |
|---:|---|
| `0` | 所有服务器均返回可解析的 DNS 响应；DNS RCODE 可以不是 NOERROR |
| `1` | 至少一个请求发生超时、网络失败或无效响应；仍尽可能输出完整报告 |
| `2` | 命令行参数或输入无效 |
| `3` | 报告输出失败或未能正常处理的内部错误 |

参数错误优先于开始网络请求；报告写入失败必须返回 `3`。在 `compare` 中，只要有一项请求失败，最终退出码为 `1`，但不得丢失其他服务器的结果。

## 10. v0.1 验收清单

- [ ] Windows 10/11 x64 与 Ubuntu 22.04+ 可以构建。
- [ ] `--help`、`--version` 输出正确。
- [ ] 可以向显式指定的 IPv4 DNS 地址查询 A 和 AAAA。
- [ ] 可以向显式指定的 IPv6 DNS 地址查询 A 和 AAAA。
- [ ] 可以显式使用 TCP 查询。
- [ ] `auto` 模式只在有效 TC 响应后进行 TCP 回退。
- [ ] 可比较至少两个 DNS 服务器，失败项不会中断其余查询。
- [ ] 正确区分有效的非 NOERROR 响应与传输失败。
- [ ] A、AAAA、CNAME、TTL 与主要响应 flags 展示正确。
- [ ] JSON 报告符合定义的结构；默认不会覆盖已有文件。
- [ ] 畸形报文测试不会导致崩溃、越界或无限循环。
- [ ] 核心自动化测试无需访问互联网即可运行。
- [ ] README 包含构建、用法、限制、退出码和隐私说明。

## 11. 建议实施顺序

### Milestone 1：协议核心

实现 DNS 查询报文构造、名称编码/解码、资源记录解析、RCODE 与 flags；用固定二进制测试用例验证，不联网。

### Milestone 2：单服务器 UDP 查询

实现跨平台 UDP 传输、超时、响应匹配和 `query` 命令；集成本地假 DNS 服务器。

### Milestone 3：TCP 与截断回退

实现 DNS over TCP 长度前缀、完整读取、超时，以及 `auto` 模式的 TC 回退。

### Milestone 4：多服务器比较与 JSON

实现 `compare`、终端汇总、JSON schema、文件覆盖保护、退出码映射。

### Milestone 5：稳定性与发布

完成畸形输入测试、Windows/Linux CI、README、版本号与 v0.1.0 发布检查。

**完成定义：** 上述验收清单全通过；至少有一组本地假 DNS 服务器集成测试覆盖正常回答、DNS 错误、超时、TC→TCP 回退和畸形响应；Windows 与 Linux CI 均通过。未经测试的功能不得在 README 中标记为已支持。

## 12. v0.2 候选功能（不属于本次 MVP）

- MX、NS、TXT、SOA、PTR 等记录类型。
- 指定轮数与延迟统计（min/median/p95/max）。
- CNAME 链摘要、差异诊断提示、Markdown 报告。
- 并发请求上限与更细化的时间统计。
- DoH/DoT、IDN、DNSSEC 状态展示。
