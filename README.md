# DNSLab

> 面向 Windows 和 Linux 的 C++23 DNS 命令行工具项目。

DNSLab 向用户指定的 DNS 服务器查询域名，展示响应、记录与耗时，帮助学习 DNS 协议和排查解析问题。

当前版本为 **0.1.0 开发版**，已支持单服务器 **UDP、TCP、DoH 和 DoT 查询**。当前请从源码构建后运行；服务器比较与 JSON 报告仍待实现。开发进度见 [TODO](docs/todo.md)。

## 1. 功能

- **域名查询**：查询 A、AAAA，展示响应码、TTL、A/AAAA/CNAME 和各组记录。
- **UDP 与 TCP**：支持显式选择传输，默认在有效 UDP 截断响应后回退 TCP。
- **DoH 与 DoT**：直接指定 HTTPS 地址或 TLS 服务器，严格校验证书和服务器身份，可指定私有 CA。
- **有限等待**：整个查询共用一个超时预算，回退、握手和部分收发不重置计时。
- **过程与错误**：显示实际传输和尝试记录，区分参数错误、查询失败与 DNS 响应码。
- **帮助与版本**：支持顶层和查询帮助，`--version` / `-V` 显示版本。

## 2. 快速开始

先按照[构建说明](docs/build.md)从源码生成程序。以下命令从仓库根目录执行。

### Windows

使用 Windows GCC 构建预设后：

```powershell
# 查看帮助
.\build-mingw-debug\dnslab.exe --help

# 查看版本
.\build-mingw-debug\dnslab.exe --version

# 普通查询，以及加密查询
.\build-mingw-debug\dnslab.exe query example.com --server 1.1.1.1
.\build-mingw-debug\dnslab.exe query example.com --doh https://cloudflare-dns.com/dns-query
.\build-mingw-debug\dnslab.exe query example.com --dot dns.google --type AAAA
```

如果使用 MSVC 预设，运行 `build-msvc-debug/dnslab.exe`。VS Code 的工具链与独立构建目录配置见[构建说明](docs/build.md#vs-code)。

### Linux

```bash
./build-linux-debug/dnslab --help
./build-linux-debug/dnslab --version
./build-linux-debug/dnslab query example.com --server 1.1.1.1 --transport tcp
./build-linux-debug/dnslab query example.com --doh https://cloudflare-dns.com/dns-query
./build-linux-debug/dnslab query example.com --dot dns.google
```

版本输出：

```text
DNSLab 0.1.0
```

## 3. 命令与选项

下表仅列出当前已经实现的用法：

| 命令或选项 | 简写 | 用途 |
| --- | --- | --- |
| `--help` | `-h` | 显示帮助并退出 |
| `--version` | `-V` | 显示版本并退出 |
| 不带参数 | — | 显示帮助 |
| `query <name>` | — | 查询一个域名或根名称 |
| `--server <endpoint>` | `-s` | 指定普通 DNS 的 IP 端点 |
| `--doh <HTTPS URL>` | — | 指定 DoH 地址 |
| `--dot <host[:port]>` | — | 指定 DoT 服务器 |
| `--type A\|AAAA` | `-t` | 查询记录类型 |
| `--transport auto\|udp\|tcp` | `-T` | 普通 DNS 的传输方式 |
| `--timeout-ms <n>` | — | 查询总预算 |
| `--ca-file <path>` | — | 加密查询使用指定 CA 文件 |

`--server`、`--doh`、`--dot` 三者选一。默认值、组合限制和退出码见[命令行接口](docs/cli.md)，名称与服务器输入规则见[输入校验](docs/validation.md)。`compare` 与报告选项尚未提供。

## 4. 从源码构建

要求 **CMake 3.25+、支持 C++23 的 `std::expected` 与 `std::print` 的编译器与标准库、CLI11、Catch2 v3、libcurl，以及用于测试的 Python 3.10+**。建议使用仓库固定的 vcpkg 清单准备依赖。

按构建说明准备 vcpkg 后，Windows GCC 可直接使用预设：

```powershell
cmake --preset mingw-debug
cmake --build --preset mingw-debug --parallel
ctest --preset mingw-debug
```

Linux 使用 `linux-debug`，MSVC 使用 `msvc-debug`。依赖安装和 VS Code 配置见[构建与测试](docs/build.md)，实际验证环境见[开发进度](docs/todo.md#验证状态)。所有测试离线运行，不访问公共 DNS。

[GitHub Actions](https://github.com/fzgma/DNSLab/actions/workflows/build-test.yml) 覆盖 Windows、Ubuntu、Arch、Debian，分别运行冒烟、单元和集成测试。Linux 编译一次后复用同一份产物，环境与版本策略见[持续集成](docs/build.md#持续集成)。

## 5. 项目结构

```text
.
├── src/
│   ├── main.cpp        # 程序入口与命令行选项
│   ├── cli/            # 终端结果与错误展示
│   ├── dns/            # 基础类型、字节工具、域名与报文处理
│   ├── net/            # 端点、查询预算与普通及加密传输
│   └── app/            # 响应匹配、单服务器查询与自动回退
├── tests/
│   ├── main.cpp        # 测试入口与 Windows 中文参数处理
│   ├── unit/           # 报文处理与网络基础测试
│   ├── integration/    # 本地模拟服务器查询测试
│   ├── support/        # 本地测试服务器辅助代码
│   ├── fixtures/       # 离线 TLS 测试证书
│   ├── runtime/        # 直接测试已有产物的入口
│   └── cli_smoke.cmake # 命令行基础行为测试
├── cmake/              # 工具链、版本信息与共享测试注册
├── .github/            # Windows/Linux 构建与测试流程
├── docs/               # 构建说明、设计与开发计划
├── CMakeLists.txt      # 构建与测试配置
├── CMakePresets.json   # Windows/Linux 共享构建预设
└── vcpkg.json          # 依赖声明
```

## 6. 限制

- 服务器比较和 JSON 报告仍待实现；暂不支持其他查询类型、DNSSEC 验证和 IDN 自动转换。
- DoH 使用 POST；DoT 不协商自定义 `dot` ALPN。加密连接失败不回退明文，也不使用代理环境变量。
- 查询会发送给指定服务器；加密服务器名称的初次解析可能使用本机配置的普通 DNS。
- 各平台验证结果与本机 IPv6 回环限制统一记录在[验证状态](docs/todo.md#验证状态)。

## 7. 文档

设计文档包含后续功能，具体支持范围以本页和程序帮助为准。

- [文档导航](docs/index.md)
- [构建与测试](docs/build.md)
- [开发进度与待办](docs/todo.md)
- [命令行接口](docs/cli.md)
- [输入校验](docs/validation.md)
- [代码风格与提交约定](docs/style.md)

## 8. 开源协议

[GNU General Public License v3.0](LICENSE)
