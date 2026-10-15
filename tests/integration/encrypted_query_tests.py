"""使用 Python 标准库与本地回环服务器验证真实查询命令。

CTest 通过 --list-cases 发现案例，并以 --executable 和 --case 单独执行。
"""

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tls"
CA_FILE = FIXTURES / "ca.pem"
EXECUTABLE = None
CASES = {}


class ChineseArgumentParser(argparse.ArgumentParser):
    """为测试入口提供中文帮助和参数错误。"""

    def format_usage(self):
        """将标准用法提示的前缀显示为中文。"""
        return super().format_usage().replace("usage: ", "用法: ", 1)

    def format_help(self):
        """将完整帮助中的用法前缀显示为中文。"""
        return super().format_help().replace("usage: ", "用法: ", 1)

    def error(self, message):
        """用中文报告无效参数，保留调用方提供的中文原因。"""
        detail = message if message == "必须指定 --executable 和 --case" else \
            "命令行参数无效，请使用 --help 查看用法"
        self.print_usage(sys.stderr)
        self.exit(2, f"参数错误: {detail}\n")


def case(function):
    """登记一个可由 CTest 单独运行的测试场景。"""
    CASES[function.__name__] = function
    return function


def require(condition, message):
    """检查测试条件，失败时给出场景说明。"""
    if not condition:
        raise AssertionError(message)


@contextmanager
def crl_server():
    """在回环地址提供签名撤销列表，并在测试结束后关闭服务。"""
    payload = (FIXTURES / "root.crl").read_bytes()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            """仅返回本测试 CA 的撤销列表，拒绝其他路径。"""
            if self.path != "/dnslab-test-root.crl":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/pkix-crl")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            """抑制 HTTP 服务的常规日志，保持测试输出清晰。"""
            pass

    class ExclusiveServer(HTTPServer):
        # POSIX 允许在 TIME_WAIT 后重新绑定，但不允许第二个监听者共享端口。
        allow_reuse_address = os.name != "nt"
        allow_reuse_port = False

        def server_bind(self):
            """按平台规则独占监听端口并允许安全的测试重绑。"""
            if os.name == "nt":
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

    try:
        server = ExclusiveServer(("127.0.0.1", 18453), Handler)
    except OSError as error:
        raise RuntimeError("无法绑定测试 CRL 地址 127.0.0.1:18453；"
                           "请检查端口是否被其他测试或进程占用，测试不会终止其他进程。") from error
    worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05),
                              name="dnslab-test-crl")
    worker.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
        require(not worker.is_alive(), "CRL 测试服务未能停止")


def read_exact(stream, length):
    """读取指定长度的数据，提前关闭或超时立即失败。"""
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError(f"对端在读取 {len(result)}/{length} 字节后关闭连接")
        result.extend(chunk)
    return bytes(result)


def response_packet(query, kind="A", rcode=0, truncated=False):
    """以请求为基础构造指定回答与状态码的 DNS 报文。"""
    result = bytearray(query)
    result[2:4] = struct.pack("!H", 0x8180 | (0x0200 if truncated else 0) | rcode)
    if kind is None:
        return bytes(result)
    result[6:8] = b"\x00\x01"
    record_type, payload = {
        "A": (1, b"\xc0\x00\x02\x0a"),
        "AAAA": (28, bytes.fromhex("20010db8000000000000000000000001")),
        "CNAME": (5, b"\x05alias\xc0\x0c"),
    }[kind]
    result.extend(b"\xc0\x0c" + struct.pack("!HHIH", record_type, 1, 60, len(payload)))
    result.extend(payload)
    return bytes(result)


def send_http(stream, body, status=200, content_type="application/dns-message",
              extra_headers=(), chunked=False, fragmented=False):
    """发送具有指定类型、状态及分块方式的 HTTP 测试响应。"""
    headers = [f"HTTP/1.1 {status} OK", f"Content-Type: {content_type}",
               "Connection: close"]
    if chunked:
        headers.append("Transfer-Encoding: chunked")
    else:
        headers.append(f"Content-Length: {len(body)}")
    headers.extend(extra_headers)
    stream.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
    if chunked:
        for offset in range(0, len(body), 7):
            part = body[offset:offset + 7]
            stream.sendall(f"{len(part):x}\r\n".encode("ascii") + part + b"\r\n")
        stream.sendall(b"0\r\n\r\n")
    elif fragmented:
        for offset in range(0, len(body), 3):
            stream.sendall(body[offset:offset + 3])
    else:
        stream.sendall(body)


class TlsServer:
    def __init__(self, transport, handler, certificate="server", handshake_delay=0,
                 expect_tls_failure=False, permit_disconnect=False):
        """准备回环监听套接字和本场景的 TLS 服务状态。"""
        self.transport = transport
        self.handler = handler
        self.certificate = certificate
        self.handshake_delay = handshake_delay
        self.expect_tls_failure = expect_tls_failure
        self.permit_disconnect = permit_disconnect
        self.stop = threading.Event()
        self.requests = []
        self.server_names = []
        self.errors = []
        self.accepted = 0
        self.active = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, name="dnslab-test-tls")

    def __enter__(self):
        """启动测试服务线程并返回当前服务对象。"""
        self.thread.start()
        return self

    def __exit__(self, exception_type, exception, tb):
        """停止监听与活动连接，回收线程并传播服务端错误。"""
        self.stop.set()
        self.listener.close()
        if self.active is not None:
            try:
                self.active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(2)
        require(not self.thread.is_alive(), "TLS 测试服务未能停止")
        if exception_type is None:
            require(not self.errors, f"TLS 测试服务失败: {self.errors!r}")

    def _serve(self):
        """在固定时限内完成 TLS 握手、读取请求并执行场景响应。"""
        end = time.monotonic() + 5
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(FIXTURES / (self.certificate + ".pem"),
                                    FIXTURES / (self.certificate + ".key"))
            context.set_servername_callback(
                lambda stream, name, selected: self.server_names.append(name))
            if self.transport == "doh":
                context.set_alpn_protocols(["http/1.1"])
            while not self.stop.is_set() and time.monotonic() < end:
                try:
                    raw, _ = self.listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self.stop.is_set():
                        return
                    raise
                self.accepted += 1
                with raw:
                    self.active = raw
                    raw.settimeout(max(0.001, end - time.monotonic()))
                    if self.stop.wait(self.handshake_delay):
                        return
                    try:
                        stream = context.wrap_socket(raw, server_side=True)
                    except (ssl.SSLError, ConnectionError):
                        if self.expect_tls_failure or self.permit_disconnect:
                            return
                        raise
                    with stream:
                        self.active = stream
                        if self.transport == "doh":
                            request = self._read_http(stream)
                        else:
                            length = struct.unpack("!H", read_exact(stream, 2))[0]
                            request = {"body": read_exact(stream, length),
                                       "alpn": stream.selected_alpn_protocol()}
                        self.requests.append(request)
                        self.handler(self, stream, request)
                    self.active = None
        except (OSError, EOFError) as error:
            if not (self.stop.is_set() or self.permit_disconnect or
                    (self.expect_tls_failure and not self.requests)):
                self.errors.append(error)
        except BaseException as error:
            self.errors.append(error)
        finally:
            self.active = None

    @staticmethod
    def _read_http(stream):
        """有界读取 HTTP 请求头与指定长度的 DNS 正文。"""
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = stream.recv(4096)
            if not chunk:
                raise EOFError("HTTP 请求头不完整")
            data.extend(chunk)
            require(len(data) <= 16384, "HTTP 请求头超长")
        header_bytes, body = bytes(data).split(b"\r\n\r\n", 1)
        lines = header_bytes.decode("ascii").split("\r\n")
        method, path, version = lines[0].split(" ")
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            headers[name.lower()] = value.strip()
        length = int(headers.get("content-length", "0"))
        require(0 < length <= 65535, "HTTP 中 DNS 请求长度无效")
        require(len(body) <= length, "HTTP 查询后出现多余字节")
        body += read_exact(stream, length - len(body))
        return {"method": method, "path": path, "version": version,
                "headers": headers, "body": body}


def invoke(server, *, transport=None, ca=True, timeout=1500, query_type="A", env=None,
           host="127.0.0.1", ca_file=None):
    """运行真实查询命令并收集退出码及 UTF-8 输出。"""
    transport = transport or server.transport
    endpoint = (f"https://{host}:{server.port}/dns-query?fixture=1" if transport == "doh"
                else f"{host}:{server.port}")
    command = [str(EXECUTABLE), "query", "example.com", "--" + transport, endpoint,
               "--type", query_type, "--timeout-ms", str(timeout)]
    if ca:
        command.extend(["--ca-file", str(ca_file if ca_file is not None else CA_FILE)])
    environment = os.environ.copy()
    if env:
        environment.update(env)
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=7, env=environment)


def check_success(result, transport, rcode="NOERROR", answer=None):
    """核对成功响应中的传输、状态码和预期回答。"""
    require(result.returncode == 0, f"退出码={result.returncode}\n{result.stdout}\n{result.stderr}")
    require(f"传输: {transport}" in result.stdout, result.stdout)
    require(f"响应码: {rcode}" in result.stdout, result.stdout)
    if answer is not None:
        require(answer in result.stdout, result.stdout)


def check_failure(result, label=None):
    """核对查询失败的退出码和中文错误分类。"""
    require(result.returncode == 1, f"预期查询失败，实际退出码={result.returncode}\n"
                                  f"{result.stdout}\n{result.stderr}")
    require("查询失败:" in result.stderr, result.stderr)
    if label is not None:
        require(label.lower() in result.stderr.lower(), result.stderr)


def check_request(server, query_type=1):
    """独立检查客户端发送的 DNS 报文字节及传输约定。"""
    require(server.accepted == 1, f"预期一个连接，实际为 {server.accepted}")
    require(len(server.requests) == 1, f"预期一个查询，实际为 {server.requests}")
    request = server.requests[0]
    wire = request["body"]
    require(len(wire) == 29, f"查询长度错误: {wire.hex()}")
    require(wire[2:12] == bytes.fromhex("01000001000000000000"), wire.hex())
    require(wire[12:] == b"\x07example\x03com\x00" + struct.pack("!HH", query_type, 1),
            wire.hex())
    if server.transport == "doh":
        require(wire[:2] == b"\x00\x00", "DoH 默认事务 ID 应为零")
        require(request["method"] == "POST", request)
        require(request["path"] == "/dns-query?fixture=1", request)
        require(request["headers"].get("content-type") == "application/dns-message", request)
        require(request["headers"].get("accept") == "application/dns-message", request)
    else:
        require(request["alpn"] is None, "DoT 不应协商 HTTP ALPN")


def answer_handler(kind="A", rcode=0):
    """生成发送指定记录类型和响应码的服务器处理器。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        response = response_packet(request["body"], kind, rcode)
        if server.transport == "doh":
            send_http(stream, response)
        else:
            stream.sendall(struct.pack("!H", len(response)) + response)
    return handler


@case
def doh_post_answers():
    """验证 DoH POST 查询能展示 A、AAAA 与 CNAME 回答。"""
    for kind, query_type, text in (("A", "a", "192.0.2.10"),
                                   ("AAAA", "AAAA", "2001:db8::1"),
                                   ("CNAME", "A", "alias.example.com.")):
        with TlsServer("doh", answer_handler(kind)) as server:
            result = invoke(server, query_type=query_type)
        check_success(result, "doh", answer=text)
        check_request(server, 28 if query_type == "AAAA" else 1)


@case
def dot_framed_answers():
    """验证 DoT 长度帧查询能展示各类支持的回答。"""
    for kind, query_type, text in (("A", "A", "192.0.2.10"),
                                   ("AAAA", "aaaa", "2001:db8::1"),
                                   ("CNAME", "A", "alias.example.com.")):
        with TlsServer("dot", answer_handler(kind)) as server:
            result = invoke(server, query_type=query_type)
        check_success(result, "dot", answer=text)
        check_request(server, 28 if query_type.upper() == "AAAA" else 1)


@case
def doh_hostname_resolution_and_sni():
    """验证 DoH 主机名解析及握手服务器名称。"""
    with TlsServer("doh", answer_handler()) as server:
        result = invoke(server, host="localhost")
    check_success(result, "doh", answer="192.0.2.10")
    check_request(server)
    require(server.server_names == ["localhost"],
            f"TLS 服务器名称不正确: {server.server_names!r}")


@case
def dot_hostname_resolution_and_sni():
    """验证 DoT 主机名解析及握手服务器名称。"""
    with TlsServer("dot", answer_handler()) as server:
        result = invoke(server, host="localhost")
    check_success(result, "dot", answer="192.0.2.10")
    check_request(server)
    require(server.server_names == ["localhost"],
            f"TLS 服务器名称不正确: {server.server_names!r}")


@case
def doh_dns_error_is_a_valid_response():
    """验证 DoH 收到 DNS 错误码仍视为传输成功。"""
    with TlsServer("doh", answer_handler(None, 3)) as server:
        result = invoke(server)
    check_success(result, "doh", "NXDOMAIN")
    check_request(server)


@case
def dot_dns_error_is_a_valid_response():
    """验证 DoT 收到 DNS 错误码仍视为传输成功。"""
    with TlsServer("dot", answer_handler(None, 2)) as server:
        result = invoke(server)
    check_success(result, "dot", "SERVFAIL")
    check_request(server)


def check_certificate_failure(transport, certificate, use_ca):
    """验证证书失败会阻止 DNS 请求发送。"""
    with TlsServer(transport, answer_handler(), certificate,
                   expect_tls_failure=True) as server:
        result = invoke(server, ca=use_ca)
    check_failure(result, "证书验证失败")
    require(not server.requests, "未通过证书验证的 TLS 对端收到了 DNS 查询")


@case
def doh_rejects_unknown_ca():
    """验证 DoH 拒绝未知 CA 签发的证书。"""
    check_certificate_failure("doh", "server", False)


@case
def dot_rejects_unknown_ca():
    """验证 DoT 拒绝未知 CA 签发的证书。"""
    check_certificate_failure("dot", "server", False)


@case
def doh_rejects_wrong_hostname():
    """验证 DoH 拒绝服务器身份不匹配的证书。"""
    check_certificate_failure("doh", "wrong-host", True)


@case
def dot_rejects_wrong_hostname():
    """验证 DoT 拒绝服务器身份不匹配的证书。"""
    check_certificate_failure("dot", "wrong-host", True)


@case
def doh_rejects_expired_certificate():
    """验证 DoH 拒绝过期证书。"""
    check_certificate_failure("doh", "expired", True)


@case
def dot_rejects_expired_certificate():
    """验证 DoT 拒绝过期证书。"""
    check_certificate_failure("dot", "expired", True)


@case
def doh_rejects_http_error_status():
    """验证 DoH 不把 HTTP 错误页面作为 DNS 响应。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        send_http(stream, response_packet(request["body"]), status=503)
    with TlsServer("doh", handler, permit_disconnect=True) as server:
        result = invoke(server)
    check_failure(result, "HTTP 状态异常")
    require("503" in result.stderr, result.stderr)
    check_request(server)


@case
def doh_rejects_wrong_content_type():
    """验证 DoH 拒绝错误的响应媒体类型。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        send_http(stream, response_packet(request["body"]), content_type="text/plain")
    with TlsServer("doh", handler) as server:
        result = invoke(server)
    check_failure(result, "响应媒体类型无效")
    check_request(server)


@case
def doh_does_not_follow_redirects():
    """验证 DoH 拒绝重定向且不连接新的目标。"""
    with socket.socket() as redirect_target:
        redirect_target.bind(("127.0.0.1", 0))
        redirect_target.listen(1)
        redirect_target.settimeout(0.1)
        port = redirect_target.getsockname()[1]
        def handler(server, stream, request):
            """发送当前测试场景需要的响应，复现相应边界条件。"""
            send_http(stream, b"", status=302,
                      extra_headers=(f"Location: https://127.0.0.1:{port}/other",))
        with TlsServer("doh", handler) as server:
            result = invoke(server)
        check_failure(result, "HTTP 状态异常")
        require("302" in result.stderr, result.stderr)
        try:
            connection, _ = redirect_target.accept()
        except TimeoutError:
            pass
        else:
            connection.close()
            raise AssertionError("客户端跟随了 HTTP 重定向")


@case
def doh_accepts_chunked_fragmented_body():
    """验证 DoH 能重组分块和分段到达的正文。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        send_http(stream, response_packet(request["body"]), chunked=True)
    with TlsServer("doh", handler) as server:
        result = invoke(server)
    check_success(result, "doh", answer="192.0.2.10")
    check_request(server)


@case
def doh_accepts_content_type_case_and_parameter():
    """验证媒体类型大小写与参数不会误拒有效 DoH 回答。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        send_http(stream, response_packet(request["body"]),
                  content_type="Application/DNS-Message; fixture=test")
    with TlsServer("doh", handler) as server:
        result = invoke(server)
    check_success(result, "doh")


@case
def doh_rejects_oversized_content_length():
    """验证 DoH 拒绝声明超出上限的正文长度。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                       b"Content-Length: 65536\r\nConnection: close\r\n\r\n")
        stream.sendall(b"x" * 65536)
    with TlsServer("doh", handler, permit_disconnect=True) as server:
        result = invoke(server)
    check_failure(result, "消息长度无效")
    check_request(server)


@case
def doh_rejects_oversized_chunked_body():
    """验证 DoH 在分块正文超过上限时停止接收。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                       b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
        for _ in range(16):
            stream.sendall(b"1000\r\n" + b"x" * 4096 + b"\r\n")
        stream.sendall(b"0\r\n\r\n")
    with TlsServer("doh", handler, permit_disconnect=True) as server:
        result = invoke(server)
    check_failure(result, "消息长度无效")
    check_request(server)


def check_maximum_message(transport):
    """验证最大合法 DNS 报文能够完整接收和展示。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        response = bytearray(response_packet(request["body"], None))
        response[6:8] = b"\x00\x01"
        response.extend(b"\xc0\x0c" + struct.pack("!HHIH", 65000, 1, 60, 65494))
        response.extend(b"\xa5" * 65494)
        require(len(response) == 65535, "测试夹具的最大 DNS 报文长度错误")
        if transport == "doh":
            send_http(stream, response)
        else:
            stream.sendall(b"\xff\xff" + response)
    with TlsServer(transport, handler) as server:
        result = invoke(server)
    check_success(result, transport)
    check_request(server)


@case
def doh_accepts_65535_byte_message():
    """验证 DoH 接受 65535 字节的完整合法消息。"""
    check_maximum_message("doh")


@case
def dot_accepts_65535_byte_message():
    """验证 DoT 接受最大长度前缀对应的完整消息。"""
    check_maximum_message("dot")


@case
def doh_rejects_premature_http_eof():
    """验证 HTTP 正文提前结束被报告为网络失败。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                       b"Content-Length: 29\r\nConnection: close\r\n\r\n\x00\x00")
    with TlsServer("doh", handler) as server:
        result = invoke(server)
    check_failure(result, "网络失败")
    check_request(server)


@case
def dot_accepts_fragmented_prefix_and_body():
    """验证 DoT 能重组分别到达的前缀与正文。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        response = response_packet(request["body"])
        stream.sendall(b"\x00")
        if server.stop.wait(0.02):
            return
        stream.sendall(bytes([len(response)]))
        for offset in range(0, len(response), 3):
            stream.sendall(response[offset:offset + 3])
    with TlsServer("dot", handler) as server:
        result = invoke(server)
    check_success(result, "dot", answer="192.0.2.10")
    check_request(server)


@case
def dot_rejects_short_frame():
    """验证 DoT 拒绝不足 DNS 头部长度的消息。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        stream.sendall(b"\x00\x0b" + b"x" * 11)
    with TlsServer("dot", handler) as server:
        result = invoke(server)
    check_failure(result, "消息长度无效")
    check_request(server)


@case
def dot_reports_eof_during_body():
    """验证 DoT 正文中途关闭不会返回部分成功。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        stream.sendall(b"\x00\x0c\x12\x34")
    with TlsServer("dot", handler) as server:
        result = invoke(server)
    check_failure(result, "网络失败")
    check_request(server)


def check_invalid_dns(transport, malformed):
    """验证畸形报文或事务不匹配会产生对应的响应错误。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        response = bytearray(response_packet(request["body"]))
        if malformed:
            response = response[:12]
        else:
            response[1] ^= 1
        if transport == "doh":
            send_http(stream, response)
        else:
            stream.sendall(struct.pack("!H", len(response)) + response)
    with TlsServer(transport, handler) as server:
        result = invoke(server)
    check_failure(result, "响应无效")
    expected_detail = "DNS 报文解析失败" if malformed else "事务 ID 不匹配"
    require(expected_detail in result.stderr, result.stderr)
    check_request(server)


@case
def doh_rejects_malformed_dns():
    """验证 DoH 拒绝结构损坏的 DNS 响应。"""
    check_invalid_dns("doh", True)


@case
def dot_rejects_malformed_dns():
    """验证 DoT 拒绝结构损坏的 DNS 响应。"""
    check_invalid_dns("dot", True)


@case
def doh_rejects_mismatched_dns_id():
    """验证 DoH 拒绝事务 ID 不匹配的响应。"""
    check_invalid_dns("doh", False)


@case
def dot_rejects_mismatched_dns_id():
    """验证 DoT 拒绝事务 ID 不匹配的响应。"""
    check_invalid_dns("dot", False)


def check_shared_deadline(transport):
    """通过握手与响应延迟验证两阶段共用同一预算。"""
    def handler(server, stream, request):
        """发送当前测试场景需要的响应，复现相应边界条件。"""
        if server.stop.wait(0.5):
            return
        answer_handler()(server, stream, request)
    with TlsServer(transport, handler, handshake_delay=0.4,
                   permit_disconnect=True) as server:
        result = invoke(server, timeout=800)
    check_failure(result, "查询超时")
    check_request(server)


@case
def doh_handshake_and_http_share_deadline():
    """验证 DoH 握手和 HTTP 交换共享预算。"""
    check_shared_deadline("doh")


@case
def dot_handshake_and_dns_share_deadline():
    """验证 DoT 握手和 DNS 交换共享预算。"""
    check_shared_deadline("dot")


@case
def encrypted_queries_accept_unicode_ca_path():
    """验证 DoH 和 DoT 能从中文目录及文件名加载同一测试 CA。"""
    with tempfile.TemporaryDirectory(prefix="DNSLab-中文证书-") as directory:
        ca_file = Path(directory) / "信任根证书.pem"
        shutil.copyfile(CA_FILE, ca_file)
        for transport in ("doh", "dot"):
            with TlsServer(transport, answer_handler()) as server:
                result = invoke(server, ca_file=ca_file)
            check_success(result, transport, answer="192.0.2.10")
            check_request(server)


@case
def encrypted_queries_ignore_proxy_environment():
    """验证加密查询不使用环境变量指定的代理。"""
    with socket.socket() as proxy:
        proxy.bind(("127.0.0.1", 0))
        proxy.listen(1)
        proxy.settimeout(0.1)
        proxy_url = f"http://127.0.0.1:{proxy.getsockname()[1]}"
        environment = {"https_proxy": proxy_url, "HTTPS_PROXY": proxy_url,
                       "all_proxy": proxy_url, "ALL_PROXY": proxy_url,
                       "no_proxy": "", "NO_PROXY": ""}
        for transport in ("doh", "dot"):
            with TlsServer(transport, answer_handler()) as server:
                result = invoke(server, env=environment)
            check_success(result, transport)
            check_request(server)
        try:
            connection, _ = proxy.accept()
        except TimeoutError:
            pass
        else:
            connection.close()
            raise AssertionError("客户端连接了环境变量中的代理")


def main():
    """发现或执行指定的离线测试并返回对应退出码。"""
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    global EXECUTABLE
    parser = ChineseArgumentParser(description=__doc__, add_help=False)
    parser._positionals.title = "位置参数"
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示此帮助并退出")
    parser.add_argument("--list-cases", action="store_true", help="列出可运行的测试案例")
    parser.add_argument("--executable", type=Path, metavar="程序路径", help="待验证的 DNSLab 程序")
    parser.add_argument("--case", choices=sorted(CASES), metavar="案例名称", help="运行指定测试案例")
    args = parser.parse_args()
    if args.list_cases:
        print("\n".join(sorted(CASES)))
        return 0
    if args.executable is None or args.case is None:
        parser.error("必须指定 --executable 和 --case")
    EXECUTABLE = args.executable.resolve()
    require(EXECUTABLE.is_file(), f"可执行文件不存在: {EXECUTABLE}")
    try:
        with crl_server():
            CASES[args.case]()
    except BaseException:
        traceback.print_exc()
        return 1
    print(f"通过 {args.case}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
