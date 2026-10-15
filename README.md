# DNSLab

> 面向 Windows 和 Linux 的 C++23 DNS 命令行工具项目。

DNSLab 计划提供域名查询和 DNS 服务器响应比较，帮助学习 DNS 协议和排查解析问题。

当前版本为 **0.1.0**，处于基础开发阶段：程序可以查看帮助和版本信息，**尚不能执行 DNS 查询**。当前请从源码构建后运行。开发进度见 [TODO](docs/todo.md)。

## 1. 功能

- **查看帮助**：显示当前支持的选项；不带参数运行也会显示帮助。
- **查看版本**：显示程序版本，当前输出为 `DNSLab 0.1.0`。
- **基础字节工具**：核心库提供带边界检查的 16 位、32 位大端整数读取与追加写入，供后续 DNS 报文处理使用。
- **域名基础处理**：核心库支持输入校验、普通名称编码与解码、大小写无关比较和特殊字符转义显示。

## 2. 快速开始

先按照[构建说明](docs/BUILD.md)从源码生成程序。以下命令从仓库根目录执行。

### Windows

使用 Ninja 构建后：

```powershell
# 查看帮助
.\build\dnslab.exe --help

# 查看版本
.\build\dnslab.exe --version
```

如果使用 Visual Studio，按构建说明中的路径运行 `build-msvc/Debug/dnslab.exe`。

### Linux

```bash
./build/dnslab --help
./build/dnslab --version
```

版本输出：

```text
DNSLab 0.1.0
```

## 3. 命令与选项

下表仅列出当前已经实现的用法：

| 选项 | 简写 | 用途 |
| --- | --- | --- |
| `--help` | `-h` | 显示帮助并退出 |
| `--version` | — | 显示版本并退出 |
| 不带参数 | — | 显示帮助 |

当前没有可用的子命令。计划中的 `query`、`compare` 及其选项见 [CLI 设计](docs/DNSLab_v0.1_MVP.md#3-cli-设计)，该设计中的待实现功能暂不可运行，`-V` 也尚未提供。

## 4. 从源码构建

要求 **CMake 3.25+、支持 C++23 和 `std::expected` 的编译器与标准库、CLI11 和 Catch2 v3**。

若 CLI11 和 Catch2 已作为 CMake 包安装，可使用 Ninja 构建：

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

依赖安装、vcpkg 配置、Windows/Linux 命令和已验证的工具链见[构建与测试](docs/BUILD.md)。所有测试离线运行，不访问公共 DNS。

## 5. 项目结构

```text
.
├── src/
│   ├── main.cpp        # 程序入口与命令行选项
│   └── dns/            # 基础类型、字节工具与域名处理
├── tests/
│   ├── unit/           # 字节工具与域名处理测试
│   └── cli_smoke.cmake # 命令行基础行为测试
├── cmake/              # 构建时生成版本信息
├── docs/               # 构建说明、设计与开发计划
├── CMakeLists.txt      # 构建与测试配置
└── vcpkg.json          # 依赖声明
```

## 6. 限制

- 尚未实现名称压缩、完整 DNS 报文解析、UDP/TCP 查询、服务器比较或 JSON 报告。
- 当前程序不会发送网络请求，不能用来检查真实域名或 DNS 服务器。
- Windows 的 MSYS2 UCRT64 GCC 构建已验证；MSVC 和 Linux 构建流程尚未在对应环境实测。

## 7. 文档

设计文档包含后续功能，具体支持范围以本页和程序帮助为准。

- [构建与测试](docs/BUILD.md)
- [开发进度与待办](docs/todo.md)
- [v0.1 功能范围与 CLI 设计](docs/DNSLab_v0.1_MVP.md)
- [项目需求](docs/DNSLab_PRD_zh-CN.md)
- [项目架构](docs/DNSLab_Architecture_v0.1.md)
- [DNS 报文编解码设计](docs/DNSLab_WireCodec_Design_v0.1.md)
- [协作与提交约定](AGENTS.md)

## 8. 开源协议

[GNU General Public License v3.0](LICENSE)
