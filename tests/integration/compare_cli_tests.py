"""通过本地回环服务器验证真实比较命令，不访问外部 DNS 服务。

CTest 通过 --list-cases 发现案例，并以 --executable 和 --case 单独执行。
"""

from contextlib import ExitStack
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import traceback

# 复用已有协议辅助时，不在源代码目录写入字节码缓存。
sys.dont_write_bytecode = True
import plain_query_cli_tests as plain


EXECUTABLE = None
CASES = {}
DIFFERENCE_FIELDS = ("RCODE", "标志", "回答", "权威记录", "附加记录", "TTL")


def case(function):
    """登记一个可由 CTest 独立执行的比较场景。"""
    CASES[function.__name__] = function
    return function


def run_arguments(arguments, expected_code):
    """执行真实命令并检查退出码，保留完整输出供断言使用。"""
    result = subprocess.run(
        [EXECUTABLE, "compare", *arguments], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=7,
    )
    plain.require(result.returncode == expected_code,
                  f"预期退出码 {expected_code}，实际为 {result.returncode}\n"
                  f"标准输出:\n{result.stdout}\n标准错误:\n{result.stderr}")
    if expected_code == 0:
        plain.require(not result.stderr, f"比较成功时出现错误输出: {result.stderr}")
    return result


def invoke(endpoints, *options, expected_code=0, name="example.com"):
    """以重复服务器选项运行比较，并检查逐台输出保持输入顺序。"""
    arguments = [name]
    for index, endpoint in enumerate(endpoints):
        arguments.extend(("--server" if index % 2 == 0 else "-s", endpoint))
    result = run_arguments([*arguments, *options], expected_code)
    plain.require(f"比较: {len(endpoints)} 台服务器" in result.stdout, result.stdout)
    plain.require("总耗时:" in result.stdout, result.stdout)
    last_position = -1
    for index, endpoint in enumerate(endpoints, start=1):
        marker = f"服务器 {index}/{len(endpoints)}\n"
        position = result.stdout.find(marker)
        plain.require(position > last_position, f"服务器输出缺失或顺序错误: {result.stdout}")
        last_position = position
        block = server_output(result, index, len(endpoints))
        plain.require(f"目标: {endpoint}\n" in block, block)
        for field in ("传输:", "耗时:", f"问题: {name}. IN", "尝试:"):
            plain.require(field in block, f"服务器 {index} 缺少 {field}: {block}")
    return result


def server_output(result, index, count):
    """取得指定服务器的独立输出，避免其他服务器的结果掩盖缺失字段。"""
    marker = f"服务器 {index}/{count}\n"
    plain.require(marker in result.stdout, f"缺少服务器分组: {result.stdout}")
    block = result.stdout.split(marker, 1)[1]
    end = f"服务器 {index + 1}/{count}\n" if index < count else "差异摘要:"
    plain.require(end in block, f"服务器分组缺少结束边界: {result.stdout}")
    return block.split(end, 1)[0]


def summary(result, successes, count):
    """取得摘要并核对成功数，确保失败项没有被计为有效响应。"""
    plain.require("差异摘要:" in result.stdout, result.stdout)
    text = result.stdout.split("差异摘要:", 1)[1]
    plain.require(f"成功响应: {successes}/{count}" in text, text)
    return text


def check_difference(result, index, *different):
    """独立断言摘要中的六项差异，防止只命中某个宽泛错误词。"""
    expected = ", ".join(
        f"{field}={'不同' if field in different else ('未发现差异' if field == 'TTL' else '相同')}"
        for field in DIFFERENCE_FIELDS
    )
    plain.require(f"服务器 {index} 与参照: {expected}" in result.stdout, result.stdout)


def record(owner, record_type, data, ttl=60):
    """编码带独立 TTL 的测试记录，不依赖被测程序的报文实现。"""
    return owner + struct.pack("!HHIH", record_type, 1, ttl, len(data)) + data


def a_response(query, address="192.0.2.10", ttl=60):
    """构造指定 IPv4 地址和 TTL 的单条回答。"""
    answer = record(b"\xc0\x0c", 1, socket.inet_pton(socket.AF_INET, address), ttl)
    return plain.response(query, [answer])


def exchange_udp(replies, *options, expected_code=0, delays=None, record_type=1,
                 name="example.com", wire_name=plain.QUESTION_NAME):
    """为多台 UDP 服务器执行一次比较，并验证各台仅收到一个有效查询。"""
    delays = delays or [0] * len(replies)
    requests = [[] for _ in replies]
    with ExitStack() as stack:
        servers = [stack.enter_context(plain.bind_socket(socket.SOCK_DGRAM)) for _ in replies]
        endpoints = [plain.endpoint(server) for server in servers]
        with ExitStack() as workers:
            for index, (server, reply, delay) in enumerate(zip(servers, replies, delays)):
                if reply is None:
                    continue

                def serve(_deadline, server=server, reply=reply, index=index, delay=delay):
                    """接收一次请求并按场景发送响应，延迟仅用于验证超时预算。"""
                    query, sender = server.recvfrom(65535)
                    requests[index].append(query)
                    plain.check_request(query, record_type, wire_name)
                    if delay:
                        threading.Event().wait(delay)
                    server.sendto(reply(query), sender)

                workers.enter_context(plain.worker(serve))
            result = invoke(endpoints, *options, expected_code=expected_code, name=name)
        for index, (server, reply) in enumerate(zip(servers, replies)):
            if reply is None:
                readable, _, _ = select.select([server], [], [], 0)
                plain.require(bool(readable), f"服务器 {index + 1} 未收到查询")
                query, _ = server.recvfrom(65535)
                requests[index].append(query)
                plain.check_request(query, record_type, wire_name)
            plain.require(len(requests[index]) == 1, f"服务器 {index + 1} 查询次数错误")
        readable, _, _ = select.select(servers, [], [], 0)
        plain.require(not readable, "比较对同一 UDP 服务器重复发送了查询")
    return result, endpoints


@case
def compare_two_servers_default_same():
    """验证默认 A 和自动模式的双服务器查询及完整一致摘要。"""
    result, endpoints = exchange_udp([a_response, a_response])
    for index in (1, 2):
        block = server_output(result, index, 2)
        for expected in ("传输: udp", "响应码: NOERROR (0)", "尝试: 1",
                         "example.com. 60 IN A 192.0.2.10"):
            plain.require(expected in block, block)
    text = summary(result, 2, 2)
    plain.require(f"参照服务器: 1 {endpoints[0]}" in text, text)
    plain.require("服务器 2: 与参照响应一致。" in text, text)
    plain.require("=不同" not in text, text)


@case
def compare_three_servers_different_answers():
    """验证三台服务器均保留回答，并分别与首个成功响应比较。"""
    result, _ = exchange_udp([
        a_response,
        lambda query: a_response(query, "192.0.2.20"),
        a_response,
    ], "-T", "udp")
    for index, address in ((1, "192.0.2.10"), (2, "192.0.2.20"), (3, "192.0.2.10")):
        plain.require(f"IN A {address}" in server_output(result, index, 3), result.stdout)
    text = summary(result, 3, 3)
    check_difference(result, 2, "回答")
    plain.require("服务器 3: 与参照响应一致。" in text, text)


@case
def compare_ttl_only_difference():
    """验证仅 TTL 改变时不将相同记录内容误判为回答差异。"""
    result, _ = exchange_udp([a_response, lambda query: a_response(query, ttl=300)])
    plain.require("example.com. 60 IN A 192.0.2.10" in server_output(result, 1, 2), result.stdout)
    plain.require("example.com. 300 IN A 192.0.2.10" in server_output(result, 2, 2), result.stdout)
    summary(result, 2, 2)
    check_difference(result, 2, "TTL")


@case
def compare_rcode_only_difference():
    """验证不同 DNS 错误响应码仍成功退出，并与其他标志差异分开。"""
    result, _ = exchange_udp([
        lambda query: plain.response(query, rcode=2),
        lambda query: plain.response(query, rcode=3),
    ])
    plain.require("响应码: SERVFAIL (2)" in server_output(result, 1, 2), result.stdout)
    plain.require("响应码: NXDOMAIN (3)" in server_output(result, 2, 2), result.stdout)
    for index in (1, 2):
        plain.require("回答: 0" in server_output(result, index, 2), result.stdout)
    summary(result, 2, 2)
    check_difference(result, 2, "RCODE")


@case
def compare_record_order_and_name_case():
    """验证回答重排及记录所有者、名称数据的 ASCII 大小写不制造差异。"""
    alias = b"\x05alias" + plain.QUESTION_NAME
    upper_owner = b"\x07EXAMPLE\x03COM\x00"
    upper_alias = b"\x05ALIAS" + upper_owner
    address = socket.inet_pton(socket.AF_INET, "192.0.2.10")

    def first(query):
        """按名称记录在先的顺序发送小写回答。"""
        return plain.response(query, [record(b"\xc0\x0c", 5, alias), record(alias, 1, address)])

    def second(query):
        """反转记录顺序并改变所有者和目标名称的大小写。"""
        return plain.response(query, [record(upper_alias, 1, address), record(upper_owner, 5, upper_alias)])

    result, _ = exchange_udp([first, second])
    plain.require("example.com. 60 IN CNAME alias.example.com." in server_output(result, 1, 2),
                  result.stdout)
    plain.require("EXAMPLE.COM. 60 IN CNAME ALIAS.EXAMPLE.COM." in server_output(result, 2, 2),
                  result.stdout)
    text = summary(result, 2, 2)
    plain.require("服务器 2: 与参照响应一致。" in text, text)
    plain.require("=不同" not in text, text)


@case
def compare_sections_and_flags():
    """验证权威、附加记录与标志差异独立展示且不污染相同回答。"""
    def reply(query, changed=False):
        """构造相同回答及不同权威和附加记录，第二份同时设置权威标志。"""
        nameserver = (b"\x03ns2" if changed else b"\x03ns1") + plain.QUESTION_NAME
        answer = record(b"\xc0\x0c", 1, socket.inet_pton(socket.AF_INET, "192.0.2.10"))
        authority = record(b"\xc0\x0c", 2, nameserver)
        additional = record(nameserver, 1, socket.inet_pton(socket.AF_INET, "192.0.2.53"))
        packet = bytearray(plain.response(query, [answer], [authority], [additional]))
        if changed:
            packet[2] |= 0x04
        return bytes(packet)

    result, _ = exchange_udp([reply, lambda query: reply(query, changed=True)])
    for index, name in ((1, "ns1"), (2, "ns2")):
        block = server_output(result, index, 2)
        for expected in ("回答: 1", "权威记录: 1", "附加记录: 1",
                         f"{name}.example.com. 60 IN A 192.0.2.53"):
            plain.require(expected in block, block)
    summary(result, 2, 2)
    check_difference(result, 2, "标志", "权威记录", "附加记录")


@case
def compare_direct_name_types_ignore_compression_and_case():
    """验证直接名称类型只比较展开语义，不将压缩布局或名称大小写当作差异。"""
    upper_data = {
        "CNAME": b"\x05ALIAS\x07EXAMPLE\x03COM\x00",
        "NS": b"\x02NS\x07EXAMPLE\x03COM\x00",
        "PTR": b"\x04HOST\x07EXAMPLE\x03COM\x00",
    }
    for kind in ("CNAME", "NS", "PTR"):
        name, wire_name, record_type, payload, _ = plain.direct_record_fixture(kind)

        def first(query):
            """返回名称黄金值，其中 CNAME 与 NS 使用问题区压缩指针。"""
            return plain.response(query, [record(b"\xc0\x0c", record_type, payload)])

        def second(query):
            """以全大写且不压缩的名称返回同一条语义记录。"""
            return plain.response(query, [record(wire_name.upper(), record_type, upper_data[kind])])

        result, _ = exchange_udp([first, second], "-t", kind.lower(), record_type=record_type,
                                 name=name, wire_name=wire_name)
        text = summary(result, 2, 2)
        plain.require("服务器 2: 与参照响应一致。" in text, text)
        plain.require("的直接" not in result.stdout, result.stdout)


@case
def compare_mx_names_and_preference():
    """验证 MX 名称的压缩及大小写等价，优先级数值变化仍单独构成回答差异。"""
    _, _, record_type, payload, _ = plain.direct_record_fixture("MX")
    alternatives = [
        payload,
        b"\x00\x0a\x04MAIL\x07EXAMPLE\x03COM\x00",
        b"\x00\x14\x04mail\xc0\x0c",
    ]
    replies = [
        lambda query, data=data: plain.response(query, [record(b"\xc0\x0c", record_type, data)])
        for data in alternatives
    ]
    result, _ = exchange_udp(replies, "--type", "mX", record_type=record_type)
    text = summary(result, 3, 3)
    plain.require("服务器 2: 与参照响应一致。" in text, text)
    plain.require("IN MX 10 mail.example.com." in server_output(result, 1, 3), result.stdout)
    plain.require("IN MX 20 mail.example.com." in server_output(result, 3, 3), result.stdout)
    check_difference(result, 3, "回答")


@case
def compare_soa_names_and_numbers():
    """验证 SOA 两个名称的语义等价，最低缓存时间变化不会被名称规范化忽略。"""
    _, _, record_type, payload, _ = plain.direct_record_fixture("SOA")
    numbers = struct.pack("!IIIII", 2026010101, 3600, 600, 86400, 60)
    alternatives = [
        payload,
        b"\x02NS\x07EXAMPLE\x03COM\x00\x0aHOSTMASTER\x07EXAMPLE\x03COM\x00" + numbers,
        payload[:-4] + struct.pack("!I", 61),
    ]
    replies = [
        lambda query, data=data: plain.response(query, [record(b"\xc0\x0c", record_type, data)])
        for data in alternatives
    ]
    result, _ = exchange_udp(replies, "--type", "sOa", record_type=record_type)
    text = summary(result, 3, 3)
    plain.require("服务器 2: 与参照响应一致。" in text, text)
    for index, minimum in ((1, 60), (3, 61)):
        expected = f"IN SOA ns.example.com. hostmaster.example.com. 2026010101 3600 600 86400 {minimum}"
        plain.require(expected in server_output(result, index, 3), result.stdout)
    check_difference(result, 3, "回答")


@case
def compare_txt_segments_and_exact_bytes():
    """验证 TXT 相同分段可比较为一致，拼接相同但分段不同或仅字节大小写不同仍有差异。"""
    alternatives = [b"\x02ab\x00\x01c", b"\x02ab\x00\x01c",
                    b"\x01a\x00\x02bc", b"\x02Ab\x00\x01c"]
    replies = [
        lambda query, data=data: plain.response(query, [record(b"\xc0\x0c", 16, data)])
        for data in alternatives
    ]
    result, _ = exchange_udp(replies, "--type", "tXt", record_type=16)
    text = summary(result, 4, 4)
    plain.require("服务器 2: 与参照响应一致。" in text, text)
    for index, expected in ((1, 'IN TXT "ab" "" "c"'), (3, 'IN TXT "a" "" "bc"'),
                            (4, 'IN TXT "Ab" "" "c"')):
        plain.require(expected in server_output(result, index, 4), result.stdout)
    check_difference(result, 3, "回答")
    check_difference(result, 4, "回答")


@case
def compare_timeout_preserves_later_results_and_budget():
    """验证首台耗尽预算后后续仍有完整预算，且参照选择首个成功响应。"""
    result, endpoints = exchange_udp(
        [None, a_response, a_response], "--timeout-ms", "500",
        expected_code=1, delays=[0, 0.25, 0],
    )
    plain.require("查询失败: 查询超时" in result.stderr, result.stderr)
    failed = server_output(result, 1, 3)
    plain.require("查询超时" in failed and "响应码:" not in failed, failed)
    for index in (2, 3):
        block = server_output(result, index, 3)
        plain.require("响应码: NOERROR (0)" in block, block)
        plain.require("example.com. 60 IN A 192.0.2.10" in block, block)
    text = summary(result, 2, 3)
    plain.require(f"参照服务器: 2 {endpoints[1]}" in text, text)
    plain.require("服务器 1: 查询失败，未参与响应差异比较。" in text, text)
    plain.require("服务器 3: 与参照响应一致。" in text, text)


@case
def compare_failed_responses_are_not_empty_answers():
    """验证错误响应和无响应保留失败信息，仅一台或零台成功时不比较。"""
    def mismatched(query):
        """构造结构合法但事务 ID 不匹配的回答。"""
        packet = bytearray(a_response(query))
        packet[0] ^= 1
        return bytes(packet)

    for final_reply, successes in ((a_response, 1), (None, 0)):
        result, _ = exchange_udp([mismatched, final_reply], "--timeout-ms", "150", expected_code=1)
        plain.require("查询失败: 响应无效: 事务 ID 不匹配" in result.stderr, result.stderr)
        first = server_output(result, 1, 2)
        plain.require("已忽略=1" in first and "响应码:" not in first, first)
        if successes:
            plain.require("example.com. 60 IN A 192.0.2.10" in server_output(result, 2, 2), result.stdout)
        else:
            plain.require("查询失败: 查询超时" in result.stderr, result.stderr)
        text = summary(result, successes, 2)
        plain.require(f"有效响应不足两份，无法比较响应差异（成功 {successes} 台，失败 {2 - successes} 台）。"
                      in text, text)
        plain.require("与参照响应一致" not in text and "=不同" not in text, text)


@case
def compare_tcp_aaaa():
    """验证同一类型和显式 TCP 模式应用于每台服务器。"""
    requests = [[], []]
    with ExitStack() as stack:
        servers = [stack.enter_context(plain.bind_socket(socket.SOCK_STREAM)) for _ in requests]
        for server in servers:
            server.listen(1)
        with ExitStack() as workers:
            for index, server in enumerate(servers):
                def serve(deadline, server=server, index=index):
                    """读取一个 TCP DNS 帧并返回 AAAA 回答。"""
                    stream, _ = server.accept()
                    with stream:
                        query = plain.read_frame(stream, deadline)
                        requests[index].append(query)
                        plain.check_request(query, 28)
                        plain.send_frame(stream, plain.answer_response(query, "AAAA"))

                workers.enter_context(plain.worker(serve))
            result = invoke([plain.endpoint(server) for server in servers], "-T", "tcp", "-t", "aAaA")
        for index, packets in enumerate(requests, start=1):
            plain.require(len(packets) == 1, "每台 TCP 服务器必须只执行一次查询")
            block = server_output(result, index, 2)
            for expected in ("传输: tcp", "尝试: 1", "问题: example.com. IN AAAA",
                             "example.com. 60 IN AAAA 2001:db8::10"):
                plain.require(expected in block, block)
        readable, _, _ = select.select(servers, [], [], 0)
        plain.require(not readable, "比较向 TCP 服务器重复建立了连接")
    text = summary(result, 2, 2)
    plain.require("服务器 2: 与参照响应一致。" in text, text)


@case
def compare_auto_fallback():
    """验证每台独立应用自动回退，保留 UDP 与 TCP 尝试且不影响响应比较。"""
    with plain.bind_socket(socket.SOCK_STREAM) as tcp:
        tcp.listen(1)
        with plain.bind_socket(socket.SOCK_DGRAM, tcp.getsockname()[1]) as first_udp, \
                plain.bind_socket(socket.SOCK_DGRAM) as second_udp:
            requests = []

            def first(deadline):
                """对第一台返回截断响应，再通过 TCP 返回完整相同问题的回答。"""
                query, sender = first_udp.recvfrom(65535)
                requests.append(query)
                plain.check_request(query)
                first_udp.sendto(plain.response(query, truncated=True), sender)
                stream, _ = tcp.accept()
                with stream:
                    packet = plain.read_frame(stream, deadline)
                    requests.append(packet)
                    plain.send_frame(stream, a_response(packet))

            def second(_deadline):
                """对第二台直接返回未截断的 UDP 回答。"""
                query, sender = second_udp.recvfrom(65535)
                plain.check_request(query)
                second_udp.sendto(a_response(query), sender)

            with plain.worker(first), plain.worker(second):
                result = invoke([plain.endpoint(first_udp), plain.endpoint(second_udp)], "--transport", "auto")
            plain.require(len(requests) == 2 and requests[0] == requests[1],
                          "同一服务器回退必须复用 UDP 请求与事务 ID")
            first_block = server_output(result, 1, 2)
            for expected in ("传输: tcp", "尝试: 2", "1. udp", "2. tcp", "TC=1", "TC=0"):
                plain.require(expected in first_block, first_block)
            second_block = server_output(result, 2, 2)
            plain.require("传输: udp" in second_block and "尝试: 1" in second_block, second_block)
            readable, _, _ = select.select([first_udp, second_udp, tcp], [], [], 0)
            plain.require(not readable, "自动模式发生额外请求或多次回退")
    text = summary(result, 2, 2)
    plain.require("服务器 2: 与参照响应一致。" in text, text)


def reject_without_network(argument_sets, expected_detail=None):
    """监听两个普通端点，确认全部非法参数在任何发送或连接之前失败。"""
    with ExitStack() as stack:
        monitored = []
        endpoints = []
        for _ in range(2):
            tcp = stack.enter_context(plain.bind_socket(socket.SOCK_STREAM))
            tcp.listen(1)
            udp = stack.enter_context(plain.bind_socket(socket.SOCK_DGRAM, tcp.getsockname()[1]))
            monitored.extend((tcp, udp))
            endpoints.append(plain.endpoint(tcp))
        for arguments in argument_sets(*endpoints):
            result = run_arguments(arguments, 2)
            plain.require("参数错误:" in result.stderr, result.stderr)
            if expected_detail is not None:
                plain.require(expected_detail in result.stderr, result.stderr)
            readable, _, _ = select.select(monitored, [], [], 0.01)
            plain.require(not readable, f"非法参数触发了网络请求: {arguments!r}")


@case
def compare_invalid_arguments_send_nothing():
    """验证数量、名称、地址、禁用选项及重复单值参数均在全部请求前拒绝。"""
    def arguments(first, second):
        """生成包含有效前置服务器的非法输入，暴露边校验边查询的问题。"""
        base = ["example.com", "-s", first, "-s", second]
        yield ["example.com"]
        yield ["example.com", "-s", first]
        yield ["-s", first, "-s", second]
        yield [*base, "extra.example"]
        yield ["example.com", "-s", first, second]
        yield ["123", "-s", first, "-s", second]
        yield [*base, "-s", "invalid.example"]
        yield [*base, "-s", "127.0.0.1:0"]
        for options in (
            ("--unknown",), ("--doh", "https://localhost/dns-query"),
            ("--dot", "localhost"), ("--ca-file", "unused.pem"),
            ("--output", "unused.json"), ("--force",),
            ("--type", "ANY"), ("--type", "AXFR"), ("--transport", "UDP"), ("--timeout-ms", "99"),
            ("--type", "A", "-t", "A"), ("-T", "udp", "--transport", "udp"),
            ("--timeout-ms", "100", "--timeout-ms", "100"), ("--server",),
        ):
            yield [*base, *options]

    reject_without_network(arguments)


@case
def compare_duplicate_endpoints_send_nothing():
    """验证重复地址及带前导零端口的规范重复地址都不会被静默去重。"""
    def arguments(first, second):
        """生成完全相同和仅端口文本不同的重复地址组合。"""
        host, port = first.rsplit(":", 1)
        normalized_duplicate = f"{host}:0{port}"
        yield ["example.com", "-s", first, "-s", first]
        yield ["example.com", "-s", first, "-s", normalized_duplicate]
        yield ["example.com", "-s", first, "-s", second, "-s", normalized_duplicate]
        yield ["example.com", "-T", "tcp", "-s", first, "-s", normalized_duplicate]

    reject_without_network(arguments, expected_detail="重复")


def main():
    """列出或执行指定的离线比较案例，并使用 UTF-8 展示结果。"""
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    global EXECUTABLE
    parser = plain.ChineseArgumentParser(description=__doc__, add_help=False)
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
