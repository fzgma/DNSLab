# 构建与测试

本文说明如何准备依赖、编译和运行测试。当前功能见[项目首页](../README.md)，平台实测结果见[开发进度](todo.md#验证状态)。

## 要求

- CMake 3.25+，以及支持 C++23 和 `std::expected` 的编译器与标准库。
- Windows 可使用 MSYS2 UCRT64 GCC 或 MSVC；Linux 使用合适版本的 GCC / libstdc++。
- Git、CLI11 和 Catch2 v3。首次下载依赖需要网络，已经构建的测试离线运行。
- 使用 Ninja 时，确保 Ninja 与编译器可从当前终端找到。MSVC 需安装 C++ 桌面开发工作负载及 Windows SDK。

项目不依赖 IDE 私有配置。所有命令从仓库根目录执行；同一构建目录不能混用不同生成器或编译器。

## 准备依赖

`vcpkg.json` 固定基线为 `20ceb8adbf0504d4b0d5e4058a32f9d4fc896391`，对应 CLI11 2.7.2 和 Catch2 3.16.0。以下步骤将 vcpkg 放入已忽略的目录，并固定其源码版本。

Windows PowerShell：

```powershell
git clone https://github.com/microsoft/vcpkg.git build-deps/vcpkg
git -C build-deps/vcpkg checkout 20ceb8adbf0504d4b0d5e4058a32f9d4fc896391
$env:VCPKG_ROOT = Join-Path $PWD 'build-deps/vcpkg'
& "$env:VCPKG_ROOT/bootstrap-vcpkg.bat" -disableMetrics
```

Linux Bash：

```bash
git clone https://github.com/microsoft/vcpkg.git build-deps/vcpkg
git -C build-deps/vcpkg checkout 20ceb8adbf0504d4b0d5e4058a32f9d4fc896391
export VCPKG_ROOT="$PWD/build-deps/vcpkg"
"$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
```

Linux 还需准备 Make、curl、zip、unzip 和 tar。已有兼容 vcpkg 时，可跳过克隆与引导，只设置 `VCPKG_ROOT`；不必切换共享安装的版本。首次配置将根据 manifest 安装依赖。

## Windows

### MSYS2 UCRT64 GCC 与 Ninja

在 PowerShell 中确保 UCRT64 的编译器、CMake 和 Ninja 位于 `PATH`，再执行：

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-mingw-static -DVCPKG_HOST_TRIPLET=x64-mingw-static
cmake --build build --parallel
ctest --test-dir build --output-on-failure
.\build\dnslab.exe --help
.\build\dnslab.exe --version
```

### MSVC

在 Developer PowerShell 中执行。示例采用 Visual Studio 2022；其他版本使用对应生成器和独立构建目录。

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build-msvc --config Debug
ctest --test-dir build-msvc -C Debug --output-on-failure
.\build-msvc\Debug\dnslab.exe --version
```

## Linux

```bash
cmake -S . -B build -G "Unix Makefiles" \
  -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/dnslab --help
./build/dnslab --version
```

默认编译器太旧时，将 `CMAKE_CXX_COMPILER` 指向支持所需标准库的新编译器，并使用新的构建目录。目标发行版见 [mvp.md](mvp.md)，列出命令不表示该平台已经实测。

## 已安装依赖

如果 CLI11 与 Catch2 v3 已提供匹配工具链的 CMake config 包，可省略 vcpkg toolchain。例如使用 Ninja：

```text
cmake -S . -B build-system -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-system --parallel
ctest --test-dir build-system --output-on-failure
```

依赖位于非默认位置时传入 `-DCMAKE_PREFIX_PATH=<依赖目录>`，或分别设置 `CLI11_DIR` 和 `Catch2_DIR`。不要复用另一种依赖配置的构建缓存。

## 配置与测试

Ninja 等单配置生成器通过 `CMAKE_BUILD_TYPE` 选择 Debug 或 Release；Visual Studio 等多配置生成器在构建时使用 `--config`，测试时使用 `-C`。运行路径随生成器和配置变化：Ninja 为 `build/dnslab.exe`（Windows）或 `build/dnslab`（Linux），上述 MSVC 示例为 `build-msvc/Debug/dnslab.exe`。

测试覆盖输入与报文处理、套接字生命周期、查询预算、UDP 收发、响应匹配和命令行基础行为，并使用本地模拟服务器验证 UDP 查询。单元与集成用例设有 10 秒上限，命令行冒烟测试为 30 秒；预算单元测试使用固定时刻，传输与查询测试只使用本机资源、回环地址和临时端口，不访问公共 DNS。测试线程由 CMake 的 `Threads::Threads` 目标配置，Windows 自动链接系统网络库，无需添加新的第三方依赖。当前结果与后续工作统一记录在 [todo.md](todo.md)。

CTest 使用三个互不重叠的标签：`smoke` 检查程序调用，`unit` 检查纯内存逻辑，`integration` 检查系统套接字、UDP 收发和本地模拟服务器。可以分别运行；多配置生成器额外传入 `-C Release` 或对应配置：

```bash
ctest --test-dir build -L '^smoke$' --output-on-failure --no-tests=error
ctest --test-dir build -L '^unit$' --output-on-failure --no-tests=error
ctest --test-dir build -L '^integration$' --output-on-failure --no-tests=error
```

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

Ubuntu 使用最新稳定发行版（包含非 LTS）的镜像别名，Debian 跟踪 stable，Arch 跟踪滚动版。每次获取当前镜像并输出系统版本；承载 Docker 的 Ubuntu runner 不代表被测发行版。别名定义参考 [Ubuntu 官方镜像](https://hub.docker.com/_/ubuntu)、[Debian 官方镜像](https://hub.docker.com/_/debian)和 [Arch 官方镜像](https://hub.docker.com/_/archlinux)。实际测试结果以对应 Actions 日志和[验证状态](todo.md#验证状态)为准。

Linux 构建任务将程序、两个测试程序及测试注册所需文件打包，三个发行版任务下载同一个包。运行环境只安装测试工具，通过 `tests/runtime` 重新注册已有程序的测试，不安装编译器或重新生成二进制。构建环境与运行环境分离，确保验证的是同一份产物在不同发行版上的行为。各任务保留测试日志，便于定位具体用例失败。
