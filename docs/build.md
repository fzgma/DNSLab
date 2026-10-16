# 构建与测试

本文说明如何准备依赖、编译和运行测试。当前功能见[项目首页](../README.md)，平台实测结果见[开发进度](todo.md#验证状态)。

## 要求

- CMake 3.25+，以及支持 C++23、`std::expected` 和 `std::print` 的编译器与标准库。
- Windows 可使用 MSYS2 UCRT64 GCC 或 MSVC；Linux 使用合适版本的 GCC / libstdc++。
- Git、CLI11、Catch2 v3、带 TLS/HTTP2/c-ares 异步解析支持的 libcurl，以及用于测试的 Python 3.10+。首次下载依赖需要网络，已经构建的测试离线运行。
- 共享预设使用 Ninja，需确保 Ninja 与编译器可从当前终端找到。MSVC 需安装 C++ 桌面开发工作负载及 Windows SDK。

项目提供共享的 [CMake 预设](../CMakePresets.json)，命令行和 VS Code 可使用同一套配置。所有命令从仓库根目录执行；同一构建目录不能混用不同生成器或编译器。配置阶段会实际编译并链接所需 C++23 功能，部分 GCC 工具链需要的 `libstdc++exp` 会自动补齐。

## 准备依赖

[依赖清单](../vcpkg.json) 固定版本基线，并为 curl 启用 `ssl`、`http2`、`c-ares`。Windows 使用 Schannel，Linux 使用 OpenSSL。首次准备仓库内的 vcpkg 时，从清单读取基线：

Windows PowerShell：

```powershell
git clone https://github.com/microsoft/vcpkg.git build-deps/vcpkg
$dnslabBaseline = (Get-Content vcpkg.json -Raw -Encoding UTF8 | ConvertFrom-Json).'builtin-baseline'
git -C build-deps/vcpkg checkout $dnslabBaseline
$env:VCPKG_ROOT = Join-Path $PWD 'build-deps/vcpkg'
& "$env:VCPKG_ROOT/bootstrap-vcpkg.bat" -disableMetrics
```

Linux Bash：

```bash
git clone https://github.com/microsoft/vcpkg.git build-deps/vcpkg
dnslab_baseline=$(python3 -c 'import json; print(json.load(open("vcpkg.json", encoding="utf-8"))["builtin-baseline"])')
git -C build-deps/vcpkg checkout "$dnslab_baseline"
export VCPKG_ROOT="$PWD/build-deps/vcpkg"
"$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
```

Linux 还需准备 Make、curl、zip、unzip、tar、Perl、pkg-config 和 ca-certificates。已有兼容 vcpkg 时，可跳过克隆与引导，只设置 `VCPKG_ROOT`；不必切换共享安装的版本。共享预设优先使用 `VCPKG_ROOT`，未设置时自动查找 `build-deps/vcpkg`。首次配置将根据依赖清单安装依赖。

## Windows

### MSYS2 UCRT64 GCC 与 Ninja

在 PowerShell 中确保 UCRT64 的编译器、CMake 和 Ninja 位于 `PATH`，再执行：

```powershell
cmake --preset mingw-debug
cmake --build --preset mingw-debug --parallel
ctest --preset mingw-debug
.\build-mingw-debug\dnslab.exe --help
.\build-mingw-debug\dnslab.exe --version
```

### MSVC

在 x64 Developer PowerShell 中执行，并确保 Ninja 位于 `PATH`。预设使用当前开发者环境中的 MSVC，不固定 Visual Studio 版本。

```powershell
cmake --preset msvc-debug
cmake --build --preset msvc-debug --parallel
ctest --preset msvc-debug
.\build-msvc-debug\dnslab.exe --version
```

## Linux

```bash
cmake --preset linux-debug
cmake --build --preset linux-debug --parallel
ctest --preset linux-debug
./build-linux-debug/dnslab --help
./build-linux-debug/dnslab --version
```

默认编译器太旧时，将 `CMAKE_CXX_COMPILER` 指向支持所需标准库的新编译器，并使用新的构建目录。目标发行版见 [mvp.md](mvp.md)，列出命令不表示该平台已经实测。

## VS Code

安装 CMake Tools 扩展，按前述步骤准备 vcpkg、编译器和 Ninja，然后打开仓库根目录。使用 `CMake: Select Configure Preset` 选择 `mingw-debug`、`msvc-debug` 或 `linux-debug`，再执行 `CMake: Configure` 和 `CMake: Build`。MSVC 预设的 x64 开发者环境可由 CMake Tools 自动加载；终端命令仍需在开发者环境中执行。

若看不到预设选项，检查项目或用户设置中的 `cmake.useCMakePresets`，将其设为 `auto` 或 `always`。出现“找不到 CLI11Config.cmake”时，确认 vcpkg 已准备完成，再使用共享预设重新配置；预设会指定工具链和独立目录，首次安装依赖仍需网络。

`.vscode/settings.json` 与 `CMakeUserPresets.json` 均不随仓库分发，以上命令不依赖它们。本机专用预设可通过 `inherits` 继承共享预设。若已有项目级 CMake Tools 参数，则保留 `cmake.useCMakePresets=never`，同时指定 `cmake.generator`、`cmake.buildDirectory` 和 `cmake.configureSettings.CMAKE_TOOLCHAIN_FILE`；该方式与选择共享预设是两种配置入口。

复用已安装的依赖时，在本地配置中设置 `VCPKG_INSTALLED_DIR`；仅在依赖齐全、与清单一致且匹配当前工具链时关闭 `VCPKG_MANIFEST_INSTALL`。清单变更后重新启用安装。已有构建目录可以保留，新配置使用独立目录，本机绝对路径不写入共享文件。

## 已安装依赖

如果 CLI11、Catch2 v3 与 libcurl 已提供匹配工具链的 CMake 配置包，可省略 vcpkg 工具链。libcurl 需要启用 TLS、HTTP/2 和 c-ares 异步解析，仅有线程解析后端也会报告能力不足。例如使用 Ninja：

```text
cmake -S . -B build-system -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-system --parallel
ctest --test-dir build-system --output-on-failure
```

依赖位于非默认位置时传入 `-DCMAKE_PREFIX_PATH=<依赖目录>`，或分别设置 `CLI11_DIR`、`Catch2_DIR` 和 `CURL_DIR`。不要复用另一种依赖配置的构建缓存。

## 配置与测试

共享预设使用 Ninja 和 Debug 配置，产物位于 `build-<预设名>`。自定义 Ninja 等单配置生成器时通过 `CMAKE_BUILD_TYPE` 选择 Debug 或 Release；Visual Studio 等多配置生成器在构建时使用 `--config`，测试时使用 `-C`，可执行文件位于对应的配置子目录。

单元与集成用例设有 10 秒上限，命令行冒烟测试为 30 秒。集成测试使用本地模拟服务器验证 UDP/TCP、自动回退、DoH 和 DoT，不访问公共 DNS。当前结果统一记录在 [todo.md](todo.md)。

加密集成测试使用 Python 标准库和仓库中的测试证书，HTTPS/TLS 监听临时端口；撤销列表服务固定使用 `127.0.0.1:18453`。资源锁只协调同一次 CTest 中的案例，不要同时从多个构建目录或独立进程运行这组测试。端口被占用时测试明确失败，详见 [TLS 测试夹具](../tests/fixtures/tls/README.md)。

CTest 使用三个互不重叠的标签：`smoke` 检查程序调用，`unit` 检查纯内存逻辑，`integration` 检查系统套接字、网络收发和本地模拟服务器。

自有测试名称与诊断使用中文。Windows 测试入口先将命令行参数转换为 UTF-8，再交给 Catch2，确保逐案例筛选不会受本机代码页影响；`smoke`、`unit`、`integration` 和 Python 案例标识保持稳定。

```bash
ctest --preset linux-debug -L '^smoke$'
ctest --preset linux-debug -L '^unit$'
ctest --preset linux-debug -L '^integration$'
```

Windows 将示例中的 `linux-debug` 换成对应预设名；预设已经启用失败详情和无测试时失败。

IPv4 和 IPv6 均为必测项；环境不支持或回环收发失败会导致测试失败，不按跳过处理。

## 持续集成

[构建与测试工作流](../.github/workflows/build-test.yml) 在推送、拉取请求和手动触发时执行，暂不配置依赖、构建或容器缓存。依赖按 `vcpkg.json` 的固定基线安装。

| 任务 | 环境 | 行为 |
| --- | --- | --- |
| Windows | `windows-latest`，MSVC x64 | 独立构建 Release，静态链接依赖及运行库，运行三类测试 |
| Linux 构建 | `manylinux_2_28_x86_64`，GCC Toolset 15 | 生成一批 x86_64 Release 产物，静态链接 C++ 运行库 |
| Ubuntu | `ubuntu:rolling` | 运行同一批 Linux 产物的三类测试 |
| Debian | `debian:stable-slim` | 运行同一批 Linux 产物的三类测试 |
| Arch | `archlinux:base` | 运行同一批 Linux 产物的三类测试 |

工作流每次获取当前镜像并输出系统版本；承载 Docker 的 Ubuntu 运行器不代表被测发行版。具体版本与验证结果以 Actions 日志和[验证状态](todo.md#验证状态)为准。

Linux 构建任务将程序、两个测试程序、构建元数据和 Catch2 发现脚本打包，三个发行版任务下载同一个包。运行任务结合当前仓库中的测试脚本与证书，通过 [tests/runtime](../tests/runtime/CMakeLists.txt) 注册已有产物；不安装编译器，也不重新编译。各任务保留测试日志。
