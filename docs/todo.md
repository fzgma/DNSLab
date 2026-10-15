# DNSLab 开发进度

当前工作见第 7 节后续迭代。第 1–6 节保留首个代码提交的范围与验收记录。

- 对应版本：v0.1.0
- 提交类型：工程基线 / Bootstrap
- 首个提交：`5d76fb2`；后续提交文案遵循 [仓库约束](../AGENTS.md)。
- 工程基线状态：已完成（Windows GCC/Ninja 验收通过）

## 1. 本次提交目标

建立一个从干净检出状态即可配置、编译、运行基础测试的 C++23 工程；为后续 DNS Wire Codec 提供统一的错误类型、字节序工具和测试框架。

**本次提交不实现真正的 DNS 查询。** 完成后程序只需支持 `--help` 与 `--version`，核心库提供经过测试的字节序基础工具。

## 2. 必须完成

### A. 工程与构建

- [x] 建立 `CMakeLists.txt`，设置项目名 `DNSLab`、项目版本 `0.1.0`。
- [x] 强制 C++23：`CMAKE_CXX_STANDARD 23`、`CMAKE_CXX_STANDARD_REQUIRED ON`、`CMAKE_CXX_EXTENSIONS OFF`。
- [x] 设定合理的最低 CMake 版本，并避免依赖某一 IDE 的隐式配置。
- [x] 建立目标：`dnslab_core`、`dnslab`、`dnslab_tests`。
- [x] 启用 CTest；测试可通过 `ctest --test-dir build --output-on-failure` 执行。
- [x] 加入 `.gitignore`，忽略 build 目录、IDE 用户配置和临时报告。

### B. 依赖

- [x] 建立 `vcpkg.json` manifest。
- [x] 第一提交只引入实际会用到的 CLI11 与 Catch2；JSON 库待 JSON 报告任务开始时再引入。
- [x] 记录可复现的 vcpkg 配置方法。若设置 `builtin-baseline`，必须使用实际验证过的 vcpkg commit，不要编造哈希。
- [x] 不引入 DNS 客户端库，不让第三方库替代本项目的 DNS wire parser。

### C. CLI 基线

- [x] 程序名称为 `dnslab`。
- [x] `dnslab --help` 能输出用法并成功退出。
- [x] `dnslab --version` 输出 `DNSLab 0.1.0`（版本字符串应由 CMake 项目版本注入，不要在多个源码文件里硬编码）。
- [x] 无参数运行时展示简要帮助。
- [x] 当前未实现 `query` / `compare` 时，不得显示这些命令已经可用；可以在帮助信息中注明功能正在开发，或暂不注册这些子命令。
- [x] CLI 解析错误通过 CLI11 的标准错误路径处理，不用 `exit()` 随意终止核心库流程。

### D. Core 基础类型与字节工具

- [x] 建立 DNS 内部类型与错误类型的最小骨架，避免在本次提交中实现完整消息解析。
- [x] 实现受边界检查的 `read_u16_be(span, offset)`。
- [x] 实现受边界检查的 `read_u32_be(span, offset)`。
- [x] 实现 `append_u16_be` 与 `append_u32_be`。
- [x] 读取函数以 `std::expected<T, E>` 报告越界；不以异常作为普通越界控制流。
- [x] 输入使用 `std::span<const std::byte>`；不使用 `reinterpret_cast` 读取网络整数。
- [x] 偏移检查先比较剩余长度，再做索引或加法，避免整数溢出和越界。
- [x] 不为本提交创建过度抽象的 ByteReader 框架；简单、集中、容易测试即可。

建议的文件形状（可在不改变职责的前提下调整）：

```text
src/
  main.cpp
  dns/
    types.hpp
    errors.hpp
    byte_utils.hpp
    byte_utils.cpp
tests/
  unit/
    byte_utils_tests.cpp
```

### E. 测试

- [x] 正常读取 `0x1234` 等 big-endian 16-bit 值。
- [x] 正常读取 `0x12345678` 等 big-endian 32-bit 值。
- [x] 测试非零 offset 的读取。
- [x] 测试空输入、剩余字节不足、offset 位于末尾以及 offset 超出范围。
- [x] 测试 16-bit/32-bit 写入得到的逐字节结果。
- [x] 测试至少一条 `--help` / `--version` CLI 冒烟路径（可以使用独立进程测试，也可用合适的轻量测试方式）。
- [x] 所有测试离线运行，不访问公共 DNS。

### F. 文档

- [x] README 写明编译器要求、CMake/vcpkg 配置、构建、测试和当前未支持网络查询的状态。
- [x] 本次只记录已经实现的功能，不提前宣称 UDP、TCP 或 DNS 解析已完成。

## 3. 验收命令

在已配置好 vcpkg 的干净工作树中，以下流程必须成功（具体 toolchain 路径按本机调整）：

```powershell
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
.\build\Debug\dnslab.exe --help
.\build\Debug\dnslab.exe --version
```

Linux 的可执行文件路径和配置命令应在 README 中给出。不要要求用户手工修改 IDE 私有配置才能构建。

## 4. 本次提交明确不做

- [ ] DNS Name 普通编码/解码与压缩指针算法。
- [ ] `parse_message`、Question/RR 解析与查询报文构造。
- [ ] UDP/TCP Socket、超时、重试与 TCP 回退。
- [ ] `query` / `compare` 的实际查询逻辑。
- [ ] JSON 报告、JSON Schema 与输出文件管理。
- [ ] DoH、DoT、DNSSEC、IDN、MX/NS/TXT/SOA。
- [ ] 多服务器并发、采样统计和排名。

这些功能不是遗漏，而是后续提交的边界。

## 5. 完成定义

- [x] CMake 能以 C++23 配置并构建全部目标。
- [x] Core 基础工具没有平台相关网络依赖。
- [x] 单元测试全部通过。
- [x] `--help` 与 `--version` 正常工作。
- [x] README 的构建步骤可复现。
- [x] `git diff --check` 无空白错误。
- [x] 变更范围只覆盖工程基线、基础字节工具、对应测试与文档。

已完成的首个提交（历史记录）：

```text
chore: bootstrap C++23 CLI and test infrastructure
```

后续功能迭代进入 DNS Name 编码/解码；压缩解码需独立实现并有专门的边界测试，不要和首次工程初始化混在一起。

## 6. 本次验收记录

- 环境：Windows / MSYS2 UCRT64 GCC 16.2.0 / CMake 4.4.3 / Ninja，Debug。
- vcpkg baseline：`20ceb8adbf0504d4b0d5e4058a32f9d4fc896391`；CLI11 2.7.2、Catch2 3.16.0。
- 配置与三个目标构建成功；编译明确使用 C++23。
- `ctest --test-dir build -C Debug --output-on-failure`：11/11 通过。
- 单元测试：10 个测试用例、140 条断言；包含空输入、截断、非零 offset 和 `SIZE_MAX`。
- CLI 冒烟测试：帮助、版本、无参数、未知选项及未实现的 query/compare，共 6 种调用。
- `dnslab --version` 输出 `DNSLab 0.1.0`；`git diff --check` 通过。
- README 包含本机实际构建步骤；MSVC/Linux 流程已记录，但尚未在对应环境执行。
- 第 4 节列出的功能保留为后续任务，本次未实现。

## 7. 后续迭代

- [x] 确定查询与比较命令的长短选项、默认值和输入规则，见 [MVP 命令行设计](DNSLab_v0.1_MVP.md#3-cli-设计)。
- [x] 约定按每台服务器整次查询计算超时，包含传输回退。
- [x] 在 [AGENTS.md](../AGENTS.md) 记录中文三段式提交文案约束。
- [x] 实现 DNS Name 普通编码/解码与边界测试。
- [x] 独立实现名称压缩解码与异常输入测试。
- [ ] 实现查询报文编码及 Header、Question、RR 解析，支持 A/AAAA/CNAME 和未知记录保留。
- [ ] 实现 UDP 查询与响应匹配，再加入 TCP 和截断回退。
- [ ] 按已确认命令行方案接入查询、比较、终端结果与 JSON 报告。
- [ ] 完成本地模拟服务器测试、Windows/Linux 验证与发布检查，详见 [架构设计](DNSLab_Architecture_v0.1.md)。

## 8. 域名处理验收记录

### 普通名称（提交 `e4e0d2a`）

- 支持 ASCII 输入校验、根名称、可选尾点、普通编码/解码、安全显示和 ASCII 大小写比较。
- 明确区分用户输入限制与报文中的原始标签字节；编码器独立校验名称长度。
- 覆盖标签 63/64 字节、完整名称 255/256 字节、截断、空输入和 `SIZE_MAX` 偏移。
- Windows GCC/Ninja Debug 构建成功；CTest 34/34 通过，单元测试 33 个用例、702 条断言通过。
- 本阶段遇到压缩指针返回明确的未支持错误；压缩处理在下一独立提交加入。

### 压缩名称

- 支持向后指针、多级引用和普通标签加指针的组合；保留原始串行消耗长度。
- 识别截断、越界、前向/自身引用、循环和展开长度超限；报告对应报文位置。
- 覆盖最大 14 位目标、超过 14 位的名称起点、301 次合法跳转，以及展开 255 字节但原始消耗 256 字节的边界。
- Windows GCC/Ninja Debug 构建成功；CTest 50/50 通过，单元测试 49 个用例、770 条断言通过。
- 单元测试设有 10 秒运行上限；所有测试离线执行，CLI 当前仍仅提供帮助与版本。
