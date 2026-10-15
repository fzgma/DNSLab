# DNSLab 构建与测试

本文记录从源码构建 DNSLab 的工具链、依赖和平台命令。程序用法见[项目首页](../README.md)。

## 构建要求

- CMake **3.25 或更新版本**。
- 支持 C++23 和 `std::expected` 的编译器及配套标准库。Windows 可使用 MSVC 或 MSYS2 UCRT64 GCC，Linux 使用 GCC / libstdc++；仅接受 `-std=c++23` 参数的旧工具链未必提供 `std::expected`。
- Git，以及 vcpkg 初次引导和安装依赖所需的网络连接。
- 依赖为 **CLI11** 和 **Catch2 v3**，在根目录 `vcpkg.json` 中声明。没有 DNS 客户端库或 JSON 库依赖。

以下命令均从仓库根目录执行，不需要修改 IDE 的私有配置。已在 Windows、MSYS2 UCRT64 GCC 16.2.0、CMake 4.4.3 和 Ninja 环境完成 Debug 构建及离线测试；下列 MSVC 与 Linux 命令尚未实测。验收记录见[工程基线清单](todo.md)。

## 准备 vcpkg

`vcpkg.json` 固定 ports 基线为 `20ceb8adbf0504d4b0d5e4058a32f9d4fc896391`，已确认该 commit 存在，对应 CLI11 **2.7.2** 和 Catch2 **3.16.0**。以下步骤同时固定 vcpkg 的源码版本，安装在已忽略的 `build-deps/vcpkg` 下。

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

已有 vcpkg 时，可以跳过克隆和引导，将 `VCPKG_ROOT` 指向其根目录：PowerShell 使用 `$env:VCPKG_ROOT = 'C:/path/to/vcpkg'`，Bash 使用 `export VCPKG_ROOT=/path/to/vcpkg`。已有版本须支持 manifest 和固定 baseline；无需切换共享安装的 checkout。如需复现上面的 vcpkg 源码版本，可另建一份固定检出。

首次配置会根据 manifest 下载和安装依赖，需要网络；运行已构建的测试不需要网络。

## Windows 构建

选择其中一种工具链。同一个构建目录不能混用不同编译器或生成器，切换时应使用新的目录。

**MSYS2 UCRT64 GCC + Ninja：** 确保 UCRT64 的 `g++`、CMake 和 Ninja 已在 PowerShell 的 `PATH` 中，然后执行：

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-mingw-static -DVCPKG_HOST_TRIPLET=x64-mingw-static
cmake --build build --parallel
ctest --test-dir build --output-on-failure
.\build\dnslab.exe --help
.\build\dnslab.exe --version
.\build\dnslab.exe
```

**MSVC：** 安装 Visual Studio 的“使用 C++ 的桌面开发”工作负载及 Windows SDK，在 Developer PowerShell 中执行。示例使用 Visual Studio 2022；其他版本应选择对应生成器。

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build-msvc --config Debug
ctest --test-dir build-msvc -C Debug --output-on-failure
.\build-msvc\Debug\dnslab.exe --help
.\build-msvc\Debug\dnslab.exe --version
```

Ninja 的可执行文件位于 `build/dnslab.exe`，Visual Studio 多配置生成器的示例路径为 `build-msvc/Debug/dnslab.exe`。构建 Release 时，修改 Ninja 的 `CMAKE_BUILD_TYPE`；MSVC 则将构建、测试和可执行文件路径中的 `Debug` 一并替换为 `Release`。

## Linux：GCC + vcpkg

准备满足上述 C++23 要求的 `g++`，以及 CMake、Git、Make、curl、zip、unzip 和 tar。完成前述 vcpkg 准备后，在 Bash 中执行：

```bash
cmake -S . -B build -G "Unix Makefiles" \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/dnslab --help
./build/dnslab --version
./build/dnslab
```

可执行文件位于 `build/dnslab`。若系统默认 `g++` 太旧，将 `CMAKE_CXX_COMPILER` 指定为已安装的新编译器路径，并使用新的构建目录重新配置。

## 已安装依赖时直接构建

如果系统或自定义安装目录中已提供 CLI11 与 Catch2 v3 的 CMake config 包，可以不传 vcpkg toolchain。使用独立构建目录，避免与已配置的 vcpkg 缓存混用。

Windows MSVC：

```powershell
cmake -S . -B build-system -G "Visual Studio 17 2022" -A x64
cmake --build build-system --config Debug
ctest --test-dir build-system -C Debug --output-on-failure
.\build-system\Debug\dnslab.exe --version
```

Linux：

```bash
cmake -S . -B build-system -G "Unix Makefiles" \
  -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Debug
cmake --build build-system --parallel
ctest --test-dir build-system --output-on-failure
./build-system/dnslab --version
```

若依赖位于非标准目录，在配置命令中增加 `-DCMAKE_PREFIX_PATH=/path/to/dependencies`，或者分别设置 `CLI11_DIR` 和 `Catch2_DIR` 为包含各自 CMake config 文件的目录。

## 测试范围

测试覆盖整数读写、域名输入校验、名称编码与普通/压缩名称解码、长度与偏移边界、指针循环、安全显示和大小写比较，以及 CLI 基础行为。单元测试设置 10 秒运行上限，防止异常解码无限等待。**所有测试离线运行，不访问公共 DNS。**

后续实现顺序及边界参见 [工程基线清单](todo.md)、[架构设计](DNSLab_Architecture_v0.1.md) 和 [Wire Codec 设计](DNSLab_WireCodec_Design_v0.1.md)。
