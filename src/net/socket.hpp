#pragma once

#include "net/endpoint.hpp"
#include "net/errors.hpp"

#include <cstdint>
#include <expected>

namespace dnslab::net {

enum class SocketTransport { Udp, Tcp };

class Socket {
public:
#if defined(_WIN32)
    using native_handle_type = std::uintptr_t;
#else
    using native_handle_type = int;
#endif

    /// 构造尚未持有系统句柄的空套接字。
    Socket() noexcept = default;
    /// 释放句柄及其关联的平台初始化引用。
    ~Socket() noexcept;

    /// 禁止复制句柄所有权，避免重复关闭。
    Socket(const Socket&) = delete;
    /// 禁止复制赋值，保持系统句柄由唯一对象拥有。
    Socket& operator=(const Socket&) = delete;
    /// 接管另一对象的句柄，并将来源置为空状态。
    Socket(Socket&& other) noexcept;
    /// 先释放现有句柄，再接管来源对象的所有权。
    Socket& operator=(Socket&& other) noexcept;

    /// 判断当前对象是否持有有效系统句柄。
    [[nodiscard]] bool valid() const noexcept {
        return handle_ != invalid_handle;
    }

    /// 借出原生句柄供系统调用使用，调用方不能关闭或转移它。
    [[nodiscard]] native_handle_type native_handle() const noexcept {
        return handle_;
    }

    /// 关闭当前句柄并置空，允许对空对象重复调用。
    void close() noexcept;

    /// 创建尚未绑定或连接的非阻塞套接字。
    // Windows 句柄禁止继承；Linux 描述符执行新程序时关闭，但 fork 仍会继承。
    [[nodiscard]] static std::expected<Socket, NetworkError>
    open(IpFamily family, SocketTransport transport);

private:
    static constexpr native_handle_type invalid_handle =
        static_cast<native_handle_type>(-1);

    /// 接管已创建的系统句柄，仅供受控的创建路径使用。
    explicit Socket(native_handle_type handle) noexcept : handle_(handle) {}

    // Windows 的有效句柄同时拥有一次成功的 WSAStartup 引用。
    native_handle_type handle_{invalid_handle};
};

} // 命名空间 dnslab::net
