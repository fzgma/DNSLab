"""使用 Python 标准库与本地回环服务器验证真实查询命令。

CTest 通过 --list-cases 发现案例，并以 --executable 和 --case 单独执行。
"""

import argparse
from contextlib import contextmanager
import errno
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from unittest.mock import patch


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


def invoke(endpoint, *options, expected_code=0, name="example.com"):
    """运行真实查询命令并收集退出码及 UTF-8 输出。"""
    result = subprocess.run(
        [EXECUTABLE, "query", name, "--server", endpoint, *options],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=7,
    )
    require(result.returncode == expected_code,
            f"预期退出码 {expected_code}，实际为 {result.returncode}\n"
            f"标准输出:\n{result.stdout}\n标准错误:\n{result.stderr}")
    if expected_code == 0:
        require(not result.stderr, f"查询成功时出现错误输出: {result.stderr}")
    return result


def check_request(query, record_type=1, wire_name=QUESTION_NAME):
    """独立检查客户端发送的 DNS 报文字节及传输约定。"""
    expected = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    expected += wire_name + struct.pack("!HH", record_type, 1)
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


def direct_record_fixture(kind, ipv6_ptr=False):
    """提供六种直接查询的独立请求名称、记录字节与完整显示黄金值。"""
    name, wire_name = "example.com", QUESTION_NAME
    fixtures = {
        "CNAME": (5, b"\x05alias\xc0\x0c", "alias.example.com."),
        "NS": (2, b"\x02ns\xc0\x0c", "ns.example.com."),
        "MX": (15, b"\x00\x0a\x04mail\xc0\x0c", "10 mail.example.com."),
        "SOA": (6, b"\x02ns\xc0\x0c\x0ahostmaster\xc0\x0c" +
                struct.pack("!IIIII", 2026010101, 3600, 600, 86400, 60),
                "ns.example.com. hostmaster.example.com. 2026010101 3600 600 86400 60"),
        "TXT": (16, b'\x0aplain text\x00\x0fA"\\\x00\t\n\r\x1b[31m\x7f\x80\xff',
                r'"plain text" "" "A\034\092\000\009\010\013\027[31m\127\128\255"'),
        "PTR": (12, b"\x04host" + QUESTION_NAME, "host.example.com."),
    }
    if kind == "PTR":
        name = "10.2.0.192.in-addr.arpa"
        wire_name = b"\x0210\x012\x010\x03192\x07in-addr\x04arpa\x00"
        if ipv6_ptr:
            name = "1." + "0." * 23 + "8.b.d.0.1.0.0.2.ip6.arpa"
            wire_name = (b"\x011" + b"\x010" * 23 +
                         b"\x018\x01b\x01d\x010\x011\x010\x010\x012\x03ip6\x04arpa\x00")
    record_type, payload, display = fixtures[kind]
    return name, wire_name, record_type, payload, display


def direct_response(query, kind, ipv6_ptr=False):
    """返回与直接查询类型一致的单条回答，名称数据可使用问题区压缩指针。"""
    _, _, record_type, payload, _ = direct_record_fixture(kind, ipv6_ptr)
    return response(query, [record(b"\xc0\x0c", record_type, payload)])


def check_direct_output(result, kind, name, display, transport):
    """逐行核对直接回答的可读字段，并禁止 TXT 原始控制字节污染终端。"""
    for text in (f"传输: {transport}", "响应码: NOERROR (0)",
                 f"问题: {name}. IN {kind}", "回答: 1"):
        require(text in result.stdout, f"直接查询缺少 {text!r}: {result.stdout}")
    expected = f"{name}. 60 IN {kind} {display}"
    require(expected in [line.strip() for line in result.stdout.splitlines()],
            f"记录显示不符合黄金值 {expected!r}: {result.stdout!r}")
    require("的直接" not in result.stdout, "匹配类型的直接回答被错误描述为缺失")
    if kind == "TXT":
        for byte in (0, 9, 13, 27, 31, 127, 128, 255):
            require(chr(byte) not in result.stdout, f"TXT 原始字节 {byte} 泄漏到终端")
        require("\ufffd" not in result.stdout, "TXT 非 ASCII 字节被错误解码为替换字符")


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


@contextmanager
def bind_udp_tcp_pair():
    """有界寻找能同时持有 UDP 与 TCP 的回环端口，避免假设两种协议的端口可用性相同。"""
    last_error = None
    last_port = None
    for _ in range(32):
        # 先从 UDP 动态范围取候选，再验证 TCP；不使用地址复用绕过占用或系统限制。
        udp = bind_socket(socket.SOCK_DGRAM)
        last_port = udp.getsockname()[1]
        try:
            tcp = bind_socket(socket.SOCK_STREAM, last_port)
        except OSError as error:
            udp.close()
            if error.errno not in (errno.EADDRINUSE, errno.EACCES, 10048, 10013) and \
                    getattr(error, "winerror", None) not in (10048, 10013):
                raise
            last_error = error
            continue
        except BaseException:
            udp.close()
            raise
        try:
            tcp.listen(1)
            yield tcp, udp
        finally:
            tcp.close()
            udp.close()
        return
    code = getattr(last_error, "winerror", None) or last_error.errno
    raise RuntimeError(
        f"32 次候选均无法同时绑定 UDP/TCP；最后候选 127.0.0.1:{last_port} "
        f"的 TCP 绑定失败，系统错误码 {code}"
    ) from last_error


def endpoint(server):
    """读取服务器实际端口并生成命令行端点文本。"""
    return f"127.0.0.1:{server.getsockname()[1]}"


def udp_exchange(reply, *options, record_type=1, expected_code=0,
                 name="example.com", wire_name=QUESTION_NAME):
    """执行一次真实 UDP 命令并验证服务端只收到一个请求。"""
    with bind_socket(socket.SOCK_DGRAM) as server:
        requests = []

        def serve(_deadline):
            """在给定截止时间内处理本场景的回环查询。"""
            query, sender = server.recvfrom(65535)
            requests.append(query)
            check_request(query, record_type, wire_name)
            server.sendto(reply(query), sender)

        with worker(serve):
            result = invoke(endpoint(server), *options, expected_code=expected_code, name=name)
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


def check_udp_direct_type(kind):
    """验证实际 UDP 请求类型、直接回答和名称；PTR 分别使用两类显式反向名称。"""
    for ipv6_ptr in ((False, True) if kind == "PTR" else (False,)):
        name, wire_name, record_type, _, display = direct_record_fixture(kind, ipv6_ptr)
        result = udp_exchange(lambda query: direct_response(query, kind, ipv6_ptr),
                              "-T", "udp", "-t", kind.lower(), record_type=record_type,
                              name=name, wire_name=wire_name)
        check_direct_output(result, kind, name, display, "udp")


@case
def plain_udp_direct_cname():
    """验证直接 CNAME 查询使用类型五并展示目标名称。"""
    check_udp_direct_type("CNAME")


@case
def plain_udp_direct_mx():
    """验证直接 MX 查询保留优先级和交换服务器名称。"""
    check_udp_direct_type("MX")


@case
def plain_udp_direct_txt():
    """验证 TXT 分段、空段与恶意控制字节的安全显示。"""
    check_udp_direct_type("TXT")


@case
def plain_udp_direct_ns():
    """验证直接 NS 查询展示名称服务器。"""
    check_udp_direct_type("NS")


@case
def plain_udp_direct_soa():
    """验证 SOA 的两个名称与五个数值按固定顺序展示。"""
    check_udp_direct_type("SOA")


@case
def plain_udp_direct_ptr():
    """验证 PTR 请求原样使用显式 IPv4 和 IPv6 反向名称。"""
    check_udp_direct_type("PTR")


@case
def plain_tcp_direct_soa():
    """验证新记录类型通过 TCP 查询时仍使用正确帧、请求类型和字段输出。"""
    name, wire_name, record_type, _, display = direct_record_fixture("SOA")
    with bind_socket(socket.SOCK_STREAM) as server:
        server.listen(1)
        requests = []

        def serve(deadline):
            """读取一个 SOA 请求并返回带压缩名称的完整 SOA 回答。"""
            stream, _ = server.accept()
            with stream:
                query = read_frame(stream, deadline)
                check_request(query, record_type, wire_name)
                requests.append(query)
                send_frame(stream, direct_response(query, "SOA"))

        with worker(serve):
            result = invoke(endpoint(server), "--transport", "tcp", "--type", "sOa", name=name)
        require(len(requests) == 1, "TCP SOA 查询次数错误")
        check_direct_output(result, "SOA", name, display, "tcp")


@case
def plain_auto_fallback_uses_identical_query():
    """验证默认回退复用同一问题和事务 ID。"""
    with bind_udp_tcp_pair() as (tcp, udp):
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
    with bind_udp_tcp_pair() as (tcp, udp):
        for options in (("--type", "ANY"), ("--type", "AXFR"), ("--type", "A", "-t", "A")):
            result = invoke(endpoint(tcp), *options, expected_code=2)
            require("参数错误:" in result.stderr, result.stderr)
        readable, _, _ = select.select([udp, tcp], [], [], 0.05)
        require(not readable, "非法命令参数发送了 UDP 数据或建立了 TCP 连接")


@case
def plain_dual_protocol_fixture_handles_bind_failures():
    """用真实套接字资源验证候选受限或占用时重选、清理、有界失败和其他错误传播。"""
    original_bind = bind_socket
    for mode in ("restricted", "busy", "exhausted", "unexpected"):
        allocated = []
        candidates = []
        failure = OSError(errno.EINVAL if mode == "unexpected" else
                          errno.EADDRINUSE if mode == "busy" else errno.EACCES,
                          "注入的候选端口绑定失败")
        if mode in ("restricted", "exhausted"):
            failure.winerror = 10013

        def controlled_bind(kind, port=0):
            """仅在第二种协议绑定时注入错误，其他步骤仍创建真实本地资源。"""
            if kind == socket.SOCK_STREAM:
                candidates.append(port)
                if mode in ("exhausted", "unexpected") or len(candidates) == 1:
                    raise failure
            server = original_bind(kind, port)
            allocated.append(server)
            return server

        with patch(__name__ + ".bind_socket", controlled_bind):
            if mode in ("restricted", "busy"):
                with bind_udp_tcp_pair() as (tcp, udp):
                    require(len(candidates) >= 2, "第二协议绑定失败后没有重选候选")
                    require(allocated[0].fileno() == -1, "失败候选的 UDP 套接字未关闭")
                    require(tcp.getsockname() == udp.getsockname(), "两种协议没有持有同一端点")
                    require(tcp.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1,
                            "返回的 TCP 套接字尚未监听")
            else:
                try:
                    with bind_udp_tcp_pair():
                        raise AssertionError("端口持续失败时仍返回了服务器")
                except RuntimeError as error:
                    require(mode == "exhausted" and error.__cause__ is failure,
                            "候选耗尽没有保留原始系统错误")
                    require(len(candidates) == 32, "候选重试没有遵守固定次数上限")
                    require(str(candidates[-1]) in str(error) and "10013" in str(error),
                            "候选耗尽缺少端口或原始错误码")
                except OSError as error:
                    require(mode == "unexpected" and error is failure and len(candidates) == 1,
                            "不属于候选冲突的错误被重试或替换")
                else:
                    raise AssertionError("候选绑定失败没有向调用方报告")
        require(all(server.fileno() == -1 for server in allocated), "双协议分配泄漏了套接字")

    for mode in ("first_protocol", "consumer"):
        allocated = []
        calls = []
        body_call_count = None
        failure = OSError(errno.EACCES, "注入的非候选绑定错误")

        def controlled_bind(kind, port=0):
            """记录分配次数，必要时只让第一协议的动态端口绑定失败。"""
            calls.append((kind, port))
            if mode == "first_protocol":
                raise failure
            server = original_bind(kind, port)
            allocated.append(server)
            return server

        with patch(__name__ + ".bind_socket", controlled_bind):
            try:
                with bind_udp_tcp_pair():
                    require(mode == "consumer", "第一协议绑定失败后仍返回了服务器")
                    body_call_count = len(calls)
                    raise failure
            except OSError as error:
                require(error is failure, "第一协议或调用方异常没有原样报告")
            else:
                raise AssertionError("第一协议或调用方异常被吞掉")
        if mode == "first_protocol":
            require(calls == [(socket.SOCK_DGRAM, 0)], "第一协议动态端口失败被错误重试")
        else:
            require(body_call_count is not None and len(calls) == body_call_count,
                    "调用方的访问错误被误当作端口冲突并重试")
        require(all(server.fileno() == -1 for server in allocated), "异常退出泄漏了套接字")


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
