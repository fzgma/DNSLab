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

核心测试覆盖整数读写、域名与端点校验、名称与完整报文处理、套接字生命周期、查询预算，以及命令行基础行为。单元测试设有 10 秒上限以暴露无限循环；预算测试使用固定时刻，套接字测试仅使用本机资源和回环地址。未来收发测试使用本地模拟服务器，不访问公共 DNS。Windows 由构建目标自动链接系统网络库，无需添加新的第三方依赖。当前结果与后续工作统一记录在 [todo.md](todo.md)。
