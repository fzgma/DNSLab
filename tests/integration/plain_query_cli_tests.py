"""CLI integration tests using only Python's standard library and IPv4 loopback.

CTest discovers --list-cases, then runs --executable PATH --case NAME.
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


def case(function):
    CASES[function.__name__] = function
    return function


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def invoke(endpoint, *options, expected_code=0):
    result = subprocess.run(
        [EXECUTABLE, "query", "example.com", "--server", endpoint, *options],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=7,
    )
    require(result.returncode == expected_code,
            f"Expected exit {expected_code}, got {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    if expected_code == 0:
        require(not result.stderr, f"Successful query wrote an error: {result.stderr}")
    return result


def check_request(query, record_type=1):
    expected = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    expected += QUESTION_NAME + struct.pack("!HH", record_type, 1)
    require(query[2:] == expected, f"Unexpected DNS request: {query.hex()}")


def record(owner, record_type, data):
    return owner + struct.pack("!HHIH", record_type, 1, 60, len(data)) + data


def response(query, answers=(), authority=(), additional=(), rcode=0, truncated=False):
    flags = 0x8180 | (0x0200 if truncated else 0) | rcode
    header = query[:2] + struct.pack("!HHHHH", flags, 1, len(answers), len(authority), len(additional))
    return header + query[12:] + b"".join((*answers, *authority, *additional))


def answer_response(query, kind):
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
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Local TCP server read exceeded its deadline")
        stream.settimeout(remaining)
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError(f"Peer closed after {len(result)} of {length} bytes")
        result.extend(chunk)
    return bytes(result)


def read_frame(stream, deadline):
    length, = struct.unpack("!H", read_exact(stream, 2, deadline))
    require(12 <= length <= 65535, f"Unexpected outgoing frame length: {length}")
    return read_exact(stream, length, deadline)


def send_frame(stream, packet):
    stream.sendall(struct.pack("!H", len(packet)) + packet)


@contextmanager
def worker(handler):
    failures = []

    def guarded():
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
        require(not thread.is_alive(), "Local server thread did not finish within its deadline")
        if failures:
            raise AssertionError(f"Local server failed: {failures[0]}") from failures[0]


def bind_socket(kind, port=0):
    server = socket.socket(socket.AF_INET, kind)
    try:
        server.bind(("127.0.0.1", port))
        server.settimeout(3)
        return server
    except BaseException:
        server.close()
        raise


def endpoint(server):
    return f"127.0.0.1:{server.getsockname()[1]}"


def udp_exchange(reply, *options, record_type=1, expected_code=0):
    with bind_socket(socket.SOCK_DGRAM) as server:
        requests = []

        def serve(_deadline):
            query, sender = server.recvfrom(65535)
            requests.append(query)
            check_request(query, record_type)
            server.sendto(reply(query), sender)

        with worker(serve):
            result = invoke(endpoint(server), *options, expected_code=expected_code)
        require(len(requests) == 1, "UDP server did not receive exactly one query")
        return result


@case
def plain_udp_records_and_sections():
    for kind, option in (("A", "a"), ("AAAA", "aAaA"), ("CNAME", "A")):
        result = udp_exchange(lambda query: answer_response(query, kind),
                              "--transport", "udp", "--type", option,
                              record_type=28 if kind == "AAAA" else 1)
        for text in ("Target: 127.0.0.1:", "Transport: udp", "Elapsed:",
                     "RCODE: NOERROR (0)", "Question: example.com. IN", "Attempts: 1"):
            require(text in result.stdout, f"Missing output {text!r}: {result.stdout}")
        if kind == "A":
            require("example.com. 60 IN A 192.0.2.10" in result.stdout, result.stdout)
            require("no direct" not in result.stdout, result.stdout)
        elif kind == "AAAA":
            require("example.com. 60 IN AAAA 2001:db8::10" in result.stdout, result.stdout)
            require("no direct" not in result.stdout, result.stdout)
        else:
            require("example.com. 60 IN CNAME alias.example.com." in result.stdout, result.stdout)
            require("alias.example.com. 60 IN A 192.0.2.10" in result.stdout, result.stdout)
            require("NOERROR response has no direct A answer for example.com." in result.stdout,
                    "A CNAME target's address must not be described as a direct answer")

    def sections(query):
        nameserver = b"\x02ns" + QUESTION_NAME
        return response(query,
                        [record(b"\xc0\x0c", 1, b"\xc0\x00\x02\x0a")],
                        [record(b"\xc0\x0c", 2, nameserver)],
                        [record(nameserver, 1, b"\xc0\x00\x02\x35")])

    result = udp_exchange(sections, "-T", "udp")
    for text in ("Answer: 1", "Authority: 1", "Additional: 1",
                 "ns.example.com. 60 IN A 192.0.2.53"):
        require(text in result.stdout, f"Missing record section {text!r}: {result.stdout}")


@case
def plain_tcp_aaaa():
    with bind_socket(socket.SOCK_STREAM) as server:
        server.listen(1)
        requests = []

        def serve(deadline):
            stream, _ = server.accept()
            with stream:
                query = read_frame(stream, deadline)
                requests.append(query)
                check_request(query, 28)
                send_frame(stream, answer_response(query, "AAAA"))

        with worker(serve):
            result = invoke(endpoint(server), "-T", "tcp", "-t", "aaaa")
        require(len(requests) == 1, "TCP server did not receive exactly one query")
        for text in ("Transport: tcp", "RCODE: NOERROR (0)", "Attempts: 1",
                     "example.com. 60 IN AAAA 2001:db8::10"):
            require(text in result.stdout, f"Missing TCP output {text!r}: {result.stdout}")


@case
def plain_auto_fallback_uses_identical_query():
    with bind_socket(socket.SOCK_STREAM) as tcp:
        tcp.listen(1)
        with bind_socket(socket.SOCK_DGRAM, tcp.getsockname()[1]) as udp:
            requests = []

            def serve(deadline):
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
                # Default mode must be auto; the client generates its own ID.
                result = invoke(endpoint(tcp), "-t", "a", "--timeout-ms", "1500")
            require(len(requests) == 2 and requests[0] == requests[1],
                    "UDP and TCP must use the same DNS packet and transaction ID")
            for text in ("Transport: tcp", "Attempts: 2", "1. udp", "2. tcp",
                         "TC=1", "TC=0", "example.com. 60 IN A 192.0.2.10"):
                require(text in result.stdout, f"Missing fallback output {text!r}: {result.stdout}")


@case
def plain_dns_rcodes_and_empty_answer():
    for rcode, name in ((0, "NOERROR"), (2, "SERVFAIL"), (3, "NXDOMAIN"), (5, "REFUSED")):
        result = udp_exchange(lambda query: response(query, rcode=rcode), "-T", "udp")
        require(f"RCODE: {name} ({rcode})" in result.stdout, result.stdout)
        require("Answer: 0" in result.stdout, result.stdout)
        require(("NOERROR response has no direct A answer" in result.stdout) == (rcode == 0),
                "Empty answers must be distinguished from DNS error rcodes")


@case
def plain_query_failures_exit_one():
    with bind_socket(socket.SOCK_DGRAM) as server:
        result = invoke(endpoint(server), "--timeout-ms", "100", expected_code=1)
        require("Query failed: Timeout" in result.stderr, result.stderr)
        require("Attempts: 1" in result.stdout, result.stdout)
        query, _ = server.recvfrom(65535)
        check_request(query)

    def mismatched(query):
        packet = bytearray(response(query))
        packet[0] ^= 1
        return bytes(packet)

    result = udp_exchange(mismatched, "--timeout-ms", "150", expected_code=1)
    require("Query failed: InvalidResponse: TransactionId" in result.stderr, result.stderr)
    require("ignored=1" in result.stdout, result.stdout)


@case
def plain_invalid_inputs_do_not_use_the_network():
    with bind_socket(socket.SOCK_STREAM) as tcp:
        tcp.listen(1)
        with bind_socket(socket.SOCK_DGRAM, tcp.getsockname()[1]) as udp:
            for options in (("--type", "MX"), ("--type", "A", "-t", "A")):
                result = invoke(endpoint(tcp), *options, expected_code=2)
                require("Argument error:" in result.stderr, result.stderr)
            readable, _, _ = select.select([udp, tcp], [], [], 0.05)
            require(not readable, "Invalid CLI inputs sent UDP data or opened TCP")


def main():
    global EXECUTABLE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-cases", action="store_true")
    parser.add_argument("--executable", type=Path)
    parser.add_argument("--case", choices=sorted(CASES))
    args = parser.parse_args()
    if args.list_cases:
        print("\n".join(sorted(CASES)))
        return 0
    if args.executable is None or args.case is None:
        parser.error("--executable and --case are required unless --list-cases is used")
    EXECUTABLE = str(args.executable.resolve())
    CASES[args.case]()
    print(f"PASS {args.case}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
