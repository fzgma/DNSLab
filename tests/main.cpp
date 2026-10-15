#include <CLI/CLI.hpp>
#include <catch2/catch_session.hpp>

#include <cstdio>
#include <print>

/// 统一命令行参数编码，使 Windows 上的中文测试名称能够与用例注册名称匹配。
int main(int argc, char* argv[]) {
    try {
        // 转换结果由参数对象持有，必须存活到测试会话结束。
        CLI::App arguments;
        return Catch::Session().run(argc, arguments.ensure_utf8(argv));
    } catch (...) {
        try {
            std::println(stderr, "测试程序启动或运行失败。");
        } catch (...) {
            // 错误流不可用时保留失败退出码，避免报告异常时再次抛出。
        }
        return 1;
    }
}
