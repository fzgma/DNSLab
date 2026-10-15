"""使用 Python 标准库与本地回环服务器验证真实查询命令。

CTest 通过 --list-cases 发现案例，并以 --executable 和 --case 单独执行。
"""

import argparse
from contextlib import contextmanager
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback


EXECUTABLE = None
CASES = {}
QUESTION_NAME = b"\x07example\x03com\x00"


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
        detail = message if message == "除 --list-cases 外，必须指定 --executable 和 --case" else \
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


def invoke(endpoint, *options, expected_code=0):
    """运行真实查询命令并收集退出码及 UTF-8 输出。"""
    result = subprocess.run(
        [EXECUTABLE, "query", "example.com", "--server", endpoint, *options],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=7,
    )
    require(result.returncode == expected_code,
            f"预期退出码 {expected_code}，实际为 {result.returncode}\n"
            f"标准输出:\n{result.stdout}\n标准错误:\n{result.stderr}")
    if expected_code == 0:
        require(not result.stderr, f"查询成功时出现错误输出: {result.stderr}")
    return result


def check_request(query, record_type=1):
    """独立检查客户端发送的 DNS 报文字节及传输约定。"""
    expected = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    expected += QUESTION_NAME + struct.pack("!HH", record_type, 1)
    require(query[2:] == expected, f"DNS 请求不符合预期: {query.hex()}")


def record(owner, record_type, data):
    """编码一条用于构造测试回答的资源记录。"""
    return owner + struct.pack("!HHIH", record_type, 1, 60, len(data)) + data


def response(query, answers=(), authority=(), additional=(), rcode=0, truncated=False):
    """组合问题与三个记录分组，生成完整 DNS 响应。"""
    flags = 0x8180 | (0x0200 if truncated else 0) | rcode
    header = query[:2] + struct.pack("!HHHHH", flags, 1, len(answers), len(authority), len(additional))
    return header + query[12:] + b"".join((*answers, *authority, *additional))


def answer_response(query, kind):
    """构造 A、AAAA 或 CNAME 链测试回答。"""
    if kind == "A":
        answers = [record(b"\xc0\x0c", 1, socket.inet_pton(socket.AF_INET, "192.0.2.10"))]
    elif kind == "AAAA":
        answers = [record(b"\xc0\x0c", 28, socket.inet_pton(socket.AF_INET6, "2001:db8::10"))]
    else:
        alias = b"\x05alias" + QUESTION_NAME
        answers = [
            record(b"\xc0\x0c", 5, alias),
            record(alias, 1, socket.inet_pton(socket.AF_INET, "192.0.2.10")),
        ]
    return response(query, answers)


def read_exact(stream, length, deadline):
    """读取指定长度的数据，提前关闭或超时立即失败。"""
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("本地 TCP 测试服务器读取超时")
        stream.settimeout(remaining)
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError(f"对端在读取 {len(result)}/{length} 字节后关闭连接")
        result.extend(chunk)
    return bytes(result)


def read_frame(stream, deadline):
    """先校验长度前缀，再完整读取一个 DNS 帧。"""
    length, = struct.unpack("!H", read_exact(stream, 2, deadline))
    require(12 <= length <= 65535, f"发出的帧长度不符合预期: {length}")
    return read_exact(stream, length, deadline)


def send_frame(stream, packet):
    """为 DNS 报文加上两字节长度前缀并发送。"""
    stream.sendall(struct.pack("!H", len(packet)) + packet)


@contextmanager
def worker(handler):
    """启动有界服务器任务并在退出时核对线程结果。"""
    failures = []

    def guarded():
        """捕获服务器线程的异常，交由主测试线程报告。"""
        try:
            handler(time.monotonic() + 3)
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=guarded, name="dnslab-plain-cli-server", daemon=True)
    thread.start()
    try:
        yield
    finally:
        thread.join(4)
        require(not thread.is_alive(), "本地服务器线程未在预算内结束")
        if failures:
            raise AssertionError(f"本地服务器失败: {failures[0]}") from failures[0]


def bind_socket(kind, port=0):
    """绑定 IPv4 回环端点并设置有限等待时间。"""
    server = socket.socket(socket.AF_INET, kind)
    try:
        server.bind(("127.0.0.1", port))
        server.settimeout(3)
        return server
    except BaseException:
        server.close()
        raise


def endpoint(server):
    """读取服务器实际端口并生成命令行端点文本。"""
    return f"127.0.0.1:{server.getsockname()[1]}"


def udp_exchange(reply, *options, record_type=1, expected_code=0):
    """执行一次真实 UDP 命令并验证服务端只收到一个请求。"""
    with bind_socket(socket.SOCK_DGRAM) as server:
        requests = []

        def serve(_deadline):
            """在给定截止时间内处理本场景的回环查询。"""
            query, sender = server.recvfrom(65535)
            requests.append(query)
            check_request(query, record_type)
            server.sendto(reply(query), sender)

        with worker(serve):
            result = invoke(endpoint(server), *options, expected_code=expected_code)
        require(len(requests) == 1, "UDP 服务器收到的查询数量不是一个")
        return result


@case
def plain_udp_records_and_sections():
    """验证普通 UDP 查询的记录格式与分组展示。"""
    for kind, option in (("A", "a"), ("AAAA", "aAaA"), ("CNAME", "A")):
        result = udp_exchange(lambda query: answer_response(query, kind),
                              "--transport", "udp", "--type", option,
                              record_type=28 if kind == "AAAA" else 1)
        for text in ("目标: 127.0.0.1:", "传输: udp", "耗时:",
                     "响应码: NOERROR (0)", "问题: example.com. IN", "尝试: 1"):
            require(text in result.stdout, f"缺少输出 {text!r}: {result.stdout}")
        if kind == "A":
            require("example.com. 60 IN A 192.0.2.10" in result.stdout, result.stdout)
            require("的直接" not in result.stdout, result.stdout)
        elif kind == "AAAA":
            require("example.com. 60 IN AAAA 2001:db8::10" in result.stdout, result.stdout)
            require("的直接" not in result.stdout, result.stdout)
        else:
            require("example.com. 60 IN CNAME alias.example.com." in result.stdout, result.stdout)
            require("alias.example.com. 60 IN A 192.0.2.10" in result.stdout, result.stdout)
            require("NOERROR 响应没有 example.com. 的直接 A 回答" in result.stdout,
                    "不能将 CNAME 目标的地址描述为直接回答")

    def sections(query):
        """构造分别包含回答、权威和附加记录的测试响应。"""
        nameserver = b"\x02ns" + QUESTION_NAME
        return response(query,
                        [record(b"\xc0\x0c", 1, b"\xc0\x00\x02\x0a")],
                        [record(b"\xc0\x0c", 2, nameserver)],
                        [record(nameserver, 1, b"\xc0\x00\x02\x35")])

    result = udp_exchange(sections, "-T", "udp")
    for text in ("回答: 1", "权威记录: 1", "附加记录: 1",
                 "ns.example.com. 60 IN A 192.0.2.53"):
        require(text in result.stdout, f"缺少记录分组 {text!r}: {result.stdout}")


@case
def plain_tcp_aaaa():
    """验证直接 TCP 查询能正确显示 IPv6 回答。"""
    with bind_socket(socket.SOCK_STREAM) as server:
        server.listen(1)
        requests = []

        def serve(deadline):
            """在给定截止时间内处理本场景的回环查询。"""
            stream, _ = server.accept()
            with stream:
                query = read_frame(stream, deadline)
                requests.append(query)
                check_request(query, 28)
                send_frame(stream, answer_response(query, "AAAA"))

        with worker(serve):
            result = invoke(endpoint(server), "-T", "tcp", "-t", "aaaa")
        require(len(requests) == 1, "TCP 服务器收到的查询数量不是一个")
        for text in ("传输: tcp", "响应码: NOERROR (0)", "尝试: 1",
                     "example.com. 60 IN AAAA 2001:db8::10"):
            require(text in result.stdout, f"缺少 TCP 输出 {text!r}: {result.stdout}")


@case
def plain_auto_fallback_uses_identical_query():
    """验证默认回退复用同一问题和事务 ID。"""
    with bind_socket(socket.SOCK_STREAM) as tcp:
        tcp.listen(1)
        with bind_socket(socket.SOCK_DGRAM, tcp.getsockname()[1]) as udp:
            requests = []

            def serve(deadline):
                """在给定截止时间内处理本场景的回环查询。"""
                query, sender = udp.recvfrom(65535)
                check_request(query)
                requests.append(query)
                udp.sendto(response(query, truncated=True), sender)
                stream, _ = tcp.accept()
                with stream:
                    tcp_query = read_frame(stream, deadline)
                    requests.append(tcp_query)
                    send_frame(stream, answer_response(tcp_query, "A"))

            with worker(serve):
                # 默认模式应为自动回退，由客户端生成事务 ID。
                result = invoke(endpoint(tcp), "-t", "a", "--timeout-ms", "1500")
            require(len(requests) == 2 and requests[0] == requests[1],
                    "UDP 与 TCP 必须使用同一报文和事务 ID")
            for text in ("传输: tcp", "尝试: 2", "1. udp", "2. tcp",
                         "TC=1", "TC=0", "example.com. 60 IN A 192.0.2.10"):
                require(text in result.stdout, f"缺少回退输出 {text!r}: {result.stdout}")


@case
def plain_dns_rcodes_and_empty_answer():
    """验证空回答提示与 DNS 错误响应码的区别。"""
    for rcode, name in ((0, "NOERROR"), (2, "SERVFAIL"), (3, "NXDOMAIN"), (5, "REFUSED")):
        result = udp_exchange(lambda query: response(query, rcode=rcode), "-T", "udp")
        require(f"响应码: {name} ({rcode})" in result.stdout, result.stdout)
        require("回答: 0" in result.stdout, result.stdout)
        require(("NOERROR 响应没有 example.com. 的直接 A 回答" in result.stdout) == (rcode == 0),
                "空回答与 DNS 错误响应码必须区分")


@case
def plain_query_failures_exit_one():
    """验证超时与不匹配响应都使用查询失败退出码。"""
    with bind_socket(socket.SOCK_DGRAM) as server:
        result = invoke(endpoint(server), "--timeout-ms", "100", expected_code=1)
        require("查询失败: 查询超时" in result.stderr, result.stderr)
        require("尝试: 1" in result.stdout, result.stdout)
        query, _ = server.recvfrom(65535)
        check_request(query)

    def mismatched(query):
        """构造事务 ID 与请求不同的有效 DNS 报文。"""
        packet = bytearray(response(query))
        packet[0] ^= 1
        return bytes(packet)

    result = udp_exchange(mismatched, "--timeout-ms", "150", expected_code=1)
    require("查询失败: 响应无效: 事务 ID 不匹配" in result.stderr, result.stderr)
    require("已忽略=1" in result.stdout, result.stdout)


@case
def plain_invalid_inputs_do_not_use_the_network():
    """验证非法参数在 UDP 发包和 TCP 连接之前被拒绝。"""
    with bind_socket(socket.SOCK_STREAM) as tcp:
        tcp.listen(1)
        with bind_socket(socket.SOCK_DGRAM, tcp.getsockname()[1]) as udp:
            for options in (("--type", "MX"), ("--type", "A", "-t", "A")):
                result = invoke(endpoint(tcp), *options, expected_code=2)
                require("参数错误:" in result.stderr, result.stderr)
            readable, _, _ = select.select([udp, tcp], [], [], 0.05)
            require(not readable, "非法命令参数发送了 UDP 数据或建立了 TCP 连接")


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
        parser.error("除 --list-cases 外，必须指定 --executable 和 --case")
    EXECUTABLE = str(args.executable.resolve())
    CASES[args.case]()
    print(f"通过 {args.case}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
