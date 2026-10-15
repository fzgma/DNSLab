# DNSLab v0.1 架构设计

- 文档版本：1.0
- 适用版本：DNSLab v0.1.0 MVP
- 语言标准：C++23
- 状态：架构决策基线

## 1. 架构目标

DNSLab 是一个跨平台 DNS 诊断 CLI。v0.1 优先完成一次查询的正确性，再扩展多服务器比较。架构以小模块、明确数据流、纯协议解析、可重复测试为目标，不预先建立通用网络框架。

## 2. 总体分层

```text
CLI
 │ 参数、命令与退出码
 ▼
Application
 │ 单次查询流程、响应匹配、TC 回退、多服务器用例
 ├───────────────┐
 ▼               ▼
DNS Wire Codec   Network
 │               │
 │ 纯字节处理     │ UDP/TCP socket、超时、收发
 └───────┬───────┘
         ▼
     QueryResult
         │
         ▼
      Reporter
    Text / JSON
```

依赖方向：

- CLI 调用 Application。
- Application 使用 DNS Wire Codec 与 Network。
- DNS Wire Codec 不依赖网络、CLI、日志和报告系统。
- Network 不解析 DNS RCODE，也不决定是否进行 TCP 回退。
- Reporter 只消费结果，不发起请求、不修改查询状态。

## 3. 模块职责

### 3.1 CLI

使用 CLI11 解析参数。v0.1 命令包括 `query` 和 `compare`，并提供 `--help` 与 `--version`。命令层负责输入验证和将最终结果映射为进程退出码；具体查询流程放在 Application。

### 3.2 Application

负责把一次查询组装为完整流程：生成事务 ID、调用编码器、使用所选传输发送请求、解析响应、验证响应与本次请求匹配、根据传输模式决定是否 TCP 回退，最后形成 `QueryResult`。

v0.1 开发顺序先完成单次查询，稳定后再实现 `compare`。MVP 范围仍包含多服务器比较，每台服务器只查询一次，不做多轮统计与排名。

### 3.3 DNS Wire Codec

纯数据处理模块。负责 DNS wire-format 查询编码、Header/Question/RR 结构解析、名称压缩、A/AAAA/CNAME 类型化解析与未知 RDATA 保留。

接口使用 `std::span<const std::byte>` 接收只读输入，必要时才拥有字节副本。错误使用 `std::expected<T, E>` 返回；禁止在解析代码中打印日志、访问网络或读取文件。

### 3.4 Network

封装跨平台 Socket 与资源生命周期：UDP 收发、TCP 连接与完整读写、超时、系统错误以及 UDP 来源端点信息。v0.1 先用同步 I/O，不引入协程、事件循环或完整异步框架。

所有超时使用 `std::chrono::steady_clock` 的绝对 deadline，不能在每次部分读取时重置完整 timeout。TCP DNS 消息使用两字节长度前缀；读取必须处理部分接收。

### 3.5 QueryResult 与 Reporter

结果模型区分：

- `transport_status`：是否成功交换并验证一份可解析响应。
- `rcode`：DNS 服务器返回的协议状态；无有效响应时为空。
- `transport_used` 与 `attempts`：记录实际使用的传输与 UDP→TCP 尝试。
- `answers`：保留 section、owner、type、TTL 和可读数据。
- `elapsed_ms`：记录本次请求耗时；没有有效响应时为空。

终端与 JSON 共用结果模型。报告写入失败由 CLI/Application 映射为退出码 3。

## 4. C++23 与依赖决策

- 必须启用 C++23：`CMAKE_CXX_STANDARD 23`、`CMAKE_CXX_STANDARD_REQUIRED ON`、`CMAKE_CXX_EXTENSIONS OFF`。
- 使用 `std::expected` 表示可恢复失败；`std::span` 表示借用的字节视图；`std::chrono::steady_clock` 管理超时；RAII 管理 Socket、文件和其他资源。
- CLI11：命令行解析。
- Catch2：单元与集成测试。
- nlohmann/json：实现 JSON 报告时引入。不要因第一阶段尚未使用而提前绑定无用依赖。
- 使用 vcpkg manifest 固定依赖和构建方式；具体 baseline 应由仓库选定并提交，不应凭空填写。
- DNS 报文的构造和解析自行实现，不使用现成 DNS 客户端库替代项目核心。

## 5. 建议目录

```text
DNSLab/
├── CMakeLists.txt
├── vcpkg.json
├── README.md
├── docs/
│   ├── DNSLab_PRD_zh-CN.md
│   ├── DNSLab_v0.1_MVP.md
│   ├── DNSLab_Architecture_v0.1.md
│   ├── DNSLab_WireCodec_Design_v0.1.md
│   └── todo.md
├── src/
│   ├── main.cpp
│   ├── cli/
│   ├── app/
│   ├── dns/
│   ├── net/
│   └── report/
└── tests/
    ├── unit/
    └── integration/
```

这是职责分区，不要求为每个很小的函数单独创建文件。v0.1 不承诺公共 C++ 库 ABI/API。

## 6. 实施阶段

1. **Commit 1 — 工程基线：** CMake/C++23、依赖、CLI help/version、核心错误类型、checked big-endian 工具与基础测试。
2. **Wire Codec：** Name 模型、普通名称编码/解码、压缩解码、Header/Question/RR、查询编码。
3. **单服务器 UDP：** Endpoint、socket RAII、deadline、响应来源和事务匹配。
4. **TCP 与回退：** 显式 TCP、TC 响应回退、尝试记录。
5. **结果与 compare：** QueryResult、文本/JSON 输出、单轮多服务器比较。
6. **稳定性：** 本地 fake DNS server、畸形报文、Windows/Linux CI、发布检查。

## 7. 质量约束

- 协议解析遇到任意不可信输入均不得越界读取、无限循环或因错误 count 分配大量内存。
- 所有纯 Wire Codec 单元测试离线运行。
- 集成测试使用本地 fake DNS server，不依赖公共 DNS。
- 不用 `reinterpret_cast` 或 packed struct 直接读取网络报文。
- 不把 NXDOMAIN、SERVFAIL、REFUSED 当作传输错误。
- 错误信息应包含稳定错误枚举与有助定位的 offset/阶段；面向用户的字符串在边界层形成。

## 8. 文档优先级

当文档存在范围差异时，按以下规则解释：

1. PRD 描述长期产品目标与 v1.0 方向。
2. `DNSLab_v0.1_MVP.md` 对 v0.1 的范围有最高优先级，并覆盖 PRD 中未计划在 v0.1 实现的功能。
3. `DNSLab_WireCodec_Design_v0.1.md` 约束 Wire Codec 的具体协议实现。
4. 本架构文档约束模块边界与依赖方向。
5. `todo.md` 只定义首个代码提交，不代表整个 MVP 的完工范围。
