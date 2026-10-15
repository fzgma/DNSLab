"""Offline CLI integration tests. All servers and certificate URLs use loopback.

Run --list-cases for CTest discovery, then --executable PATH --case CASE_NAME.
Only Python's standard library is required; certificates are public test data.
"""

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tls"
CA_FILE = FIXTURES / "ca.pem"
EXECUTABLE = None
CASES = {}


def case(function):
    CASES[function.__name__] = function
    return function


def require(condition, message):
    if not condition:
        raise AssertionError(message)


@contextmanager
def crl_server():
    payload = (FIXTURES / "root.crl").read_bytes()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
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
            pass

    class ExclusiveServer(HTTPServer):
        # POSIX reuse permits rebinding after TIME_WAIT, not a second listener.
        allow_reuse_address = os.name != "nt"
        allow_reuse_port = False

        def server_bind(self):
            if os.name == "nt":
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

    try:
        server = ExclusiveServer(("127.0.0.1", 18453), Handler)
    except OSError as error:
        raise RuntimeError("Cannot bind test CRL endpoint 127.0.0.1:18453; "
                           "ensure no other test/process owns it. No process was stopped.") from error
    worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05),
                              name="dnslab-test-crl")
    worker.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
        require(not worker.is_alive(), "CRL fixture did not stop")


def read_exact(stream, length):
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError(f"peer closed after {len(result)} of {length} bytes")
        result.extend(chunk)
    return bytes(result)


def response_packet(query, kind="A", rcode=0, truncated=False):
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
    headers = [f"HTTP/1.1 {status} Test response", f"Content-Type: {content_type}",
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
        self.thread.start()
        return self

    def __exit__(self, exception_type, exception, tb):
        self.stop.set()
        self.listener.close()
        if self.active is not None:
            try:
                self.active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(2)
        require(not self.thread.is_alive(), "TLS fixture did not stop")
        if exception_type is None:
            require(not self.errors, f"TLS fixture failed: {self.errors!r}")

    def _serve(self):
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
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = stream.recv(4096)
            if not chunk:
                raise EOFError("incomplete HTTP headers")
            data.extend(chunk)
            require(len(data) <= 16384, "oversized HTTP request headers")
        header_bytes, body = bytes(data).split(b"\r\n\r\n", 1)
        lines = header_bytes.decode("ascii").split("\r\n")
        method, path, version = lines[0].split(" ")
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            headers[name.lower()] = value.strip()
        length = int(headers.get("content-length", "0"))
        require(0 < length <= 65535, "invalid HTTP DNS request size")
        require(len(body) <= length, "unexpected bytes after HTTP query")
        body += read_exact(stream, length - len(body))
        return {"method": method, "path": path, "version": version,
                "headers": headers, "body": body}


def invoke(server, *, transport=None, ca=True, timeout=1500, query_type="A", env=None,
           host="127.0.0.1"):
    transport = transport or server.transport
    endpoint = (f"https://{host}:{server.port}/dns-query?fixture=1" if transport == "doh"
                else f"{host}:{server.port}")
    command = [str(EXECUTABLE), "query", "example.com", "--" + transport, endpoint,
               "--type", query_type, "--timeout-ms", str(timeout)]
    if ca:
        command.extend(["--ca-file", str(CA_FILE)])
    environment = os.environ.copy()
    if env:
        environment.update(env)
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=7, env=environment)


def check_success(result, transport, rcode="NOERROR", answer=None):
    require(result.returncode == 0, f"exit={result.returncode}\n{result.stdout}\n{result.stderr}")
    require(f"Transport: {transport}" in result.stdout, result.stdout)
    require(f"RCODE: {rcode}" in result.stdout, result.stdout)
    if answer is not None:
        require(answer in result.stdout, result.stdout)


def check_failure(result, label=None):
    require(result.returncode == 1, f"expected query failure, exit={result.returncode}\n"
                                  f"{result.stdout}\n{result.stderr}")
    require("Query failed:" in result.stderr, result.stderr)
    if label is not None:
        require(label.lower() in result.stderr.lower(), result.stderr)


def check_request(server, query_type=1):
    require(server.accepted == 1, f"expected one connection, got {server.accepted}")
    require(len(server.requests) == 1, f"expected one query, got {server.requests}")
    request = server.requests[0]
    wire = request["body"]
    require(len(wire) == 29, f"wrong query size: {wire.hex()}")
    require(wire[2:12] == bytes.fromhex("01000001000000000000"), wire.hex())
    require(wire[12:] == b"\x07example\x03com\x00" + struct.pack("!HH", query_type, 1),
            wire.hex())
    if server.transport == "doh":
        require(wire[:2] == b"\x00\x00", "DoH should default to ID zero")
        require(request["method"] == "POST", request)
        require(request["path"] == "/dns-query?fixture=1", request)
        require(request["headers"].get("content-type") == "application/dns-message", request)
        require(request["headers"].get("accept") == "application/dns-message", request)
    else:
        require(request["alpn"] is None, "DoT must not negotiate an HTTP ALPN")


def answer_handler(kind="A", rcode=0):
    def handler(server, stream, request):
        response = response_packet(request["body"], kind, rcode)
        if server.transport == "doh":
            send_http(stream, response)
        else:
            stream.sendall(struct.pack("!H", len(response)) + response)
    return handler


@case
def doh_post_answers():
    for kind, query_type, text in (("A", "a", "192.0.2.10"),
                                   ("AAAA", "AAAA", "2001:db8::1"),
                                   ("CNAME", "A", "alias.example.com.")):
        with TlsServer("doh", answer_handler(kind)) as server:
            result = invoke(server, query_type=query_type)
        check_success(result, "doh", answer=text)
        check_request(server, 28 if query_type == "AAAA" else 1)


@case
def dot_framed_answers():
    for kind, query_type, text in (("A", "A", "192.0.2.10"),
                                   ("AAAA", "aaaa", "2001:db8::1"),
                                   ("CNAME", "A", "alias.example.com.")):
        with TlsServer("dot", answer_handler(kind)) as server:
            result = invoke(server, query_type=query_type)
        check_success(result, "dot", answer=text)
        check_request(server, 28 if query_type.upper() == "AAAA" else 1)


@case
def doh_hostname_resolution_and_sni():
    with TlsServer("doh", answer_handler()) as server:
        result = invoke(server, host="localhost")
    check_success(result, "doh", answer="192.0.2.10")
    check_request(server)
    require(server.server_names == ["localhost"],
            f"incorrect TLS server name: {server.server_names!r}")


@case
def dot_hostname_resolution_and_sni():
    with TlsServer("dot", answer_handler()) as server:
        result = invoke(server, host="localhost")
    check_success(result, "dot", answer="192.0.2.10")
    check_request(server)
    require(server.server_names == ["localhost"],
            f"incorrect TLS server name: {server.server_names!r}")


@case
def doh_dns_error_is_a_valid_response():
    with TlsServer("doh", answer_handler(None, 3)) as server:
        result = invoke(server)
    check_success(result, "doh", "NXDOMAIN")
    check_request(server)


@case
def dot_dns_error_is_a_valid_response():
    with TlsServer("dot", answer_handler(None, 2)) as server:
        result = invoke(server)
    check_success(result, "dot", "SERVFAIL")
    check_request(server)


def check_certificate_failure(transport, certificate, use_ca):
    with TlsServer(transport, answer_handler(), certificate,
                   expect_tls_failure=True) as server:
        result = invoke(server, ca=use_ca)
    check_failure(result, "certificate")
    require(not server.requests, "unverified TLS peer received a DNS query")


@case
def doh_rejects_unknown_ca():
    check_certificate_failure("doh", "server", False)


@case
def dot_rejects_unknown_ca():
    check_certificate_failure("dot", "server", False)


@case
def doh_rejects_wrong_hostname():
    check_certificate_failure("doh", "wrong-host", True)


@case
def dot_rejects_wrong_hostname():
    check_certificate_failure("dot", "wrong-host", True)


@case
def doh_rejects_expired_certificate():
    check_certificate_failure("doh", "expired", True)


@case
def dot_rejects_expired_certificate():
    check_certificate_failure("dot", "expired", True)


@case
def doh_rejects_http_error_status():
    def handler(server, stream, request):
        send_http(stream, response_packet(request["body"]), status=503)
    with TlsServer("doh", handler, permit_disconnect=True) as server:
        result = invoke(server)
    check_failure(result, "HttpStatus")
    require("503" in result.stderr, result.stderr)
    check_request(server)


@case
def doh_rejects_wrong_content_type():
    def handler(server, stream, request):
        send_http(stream, response_packet(request["body"]), content_type="text/plain")
    with TlsServer("doh", handler) as server:
        result = invoke(server)
    check_failure(result, "InvalidContentType")
    check_request(server)


@case
def doh_does_not_follow_redirects():
    with socket.socket() as redirect_target:
        redirect_target.bind(("127.0.0.1", 0))
        redirect_target.listen(1)
        redirect_target.settimeout(0.1)
        port = redirect_target.getsockname()[1]
        def handler(server, stream, request):
            send_http(stream, b"", status=302,
                      extra_headers=(f"Location: https://127.0.0.1:{port}/other",))
        with TlsServer("doh", handler) as server:
            result = invoke(server)
        check_failure(result, "HttpStatus")
        require("302" in result.stderr, result.stderr)
        try:
            connection, _ = redirect_target.accept()
        except TimeoutError:
            pass
        else:
            connection.close()
            raise AssertionError("client followed HTTP redirect")


@case
def doh_accepts_chunked_fragmented_body():
    def handler(server, stream, request):
        send_http(stream, response_packet(request["body"]), chunked=True)
    with TlsServer("doh", handler) as server:
        result = invoke(server)
    check_success(result, "doh", answer="192.0.2.10")
    check_request(server)


@case
def doh_accepts_content_type_case_and_parameter():
    def handler(server, stream, request):
        send_http(stream, response_packet(request["body"]),
                  content_type="Application/DNS-Message; fixture=test")
    with TlsServer("doh", handler) as server:
        result = invoke(server)
    check_success(result, "doh")


@case
def doh_rejects_oversized_content_length():
    def handler(server, stream, request):
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                       b"Content-Length: 65536\r\nConnection: close\r\n\r\n")
        stream.sendall(b"x" * 65536)
    with TlsServer("doh", handler, permit_disconnect=True) as server:
        result = invoke(server)
    check_failure(result, "InvalidMessageLength")
    check_request(server)


@case
def doh_rejects_oversized_chunked_body():
    def handler(server, stream, request):
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                       b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
        for _ in range(16):
            stream.sendall(b"1000\r\n" + b"x" * 4096 + b"\r\n")
        stream.sendall(b"0\r\n\r\n")
    with TlsServer("doh", handler, permit_disconnect=True) as server:
        result = invoke(server)
    check_failure(result, "InvalidMessageLength")
    check_request(server)


def check_maximum_message(transport):
    def handler(server, stream, request):
        response = bytearray(response_packet(request["body"], None))
        response[6:8] = b"\x00\x01"
        response.extend(b"\xc0\x0c" + struct.pack("!HHIH", 65000, 1, 60, 65494))
        response.extend(b"\xa5" * 65494)
        require(len(response) == 65535, "fixture maximum DNS message has wrong length")
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
    check_maximum_message("doh")


@case
def dot_accepts_65535_byte_message():
    check_maximum_message("dot")


@case
def doh_rejects_premature_http_eof():
    def handler(server, stream, request):
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                       b"Content-Length: 29\r\nConnection: close\r\n\r\n\x00\x00")
    with TlsServer("doh", handler) as server:
        result = invoke(server)
    check_failure(result, "Network")
    check_request(server)


@case
def dot_accepts_fragmented_prefix_and_body():
    def handler(server, stream, request):
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
    def handler(server, stream, request):
        stream.sendall(b"\x00\x0b" + b"x" * 11)
    with TlsServer("dot", handler) as server:
        result = invoke(server)
    check_failure(result, "InvalidMessageLength")
    check_request(server)


@case
def dot_reports_eof_during_body():
    def handler(server, stream, request):
        stream.sendall(b"\x00\x0c\x12\x34")
    with TlsServer("dot", handler) as server:
        result = invoke(server)
    check_failure(result, "Network")
    check_request(server)


def check_invalid_dns(transport, malformed):
    def handler(server, stream, request):
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
    check_failure(result, "InvalidResponse")
    expected_detail = "DNS parse error" if malformed else "TransactionId"
    require(expected_detail in result.stderr, result.stderr)
    check_request(server)


@case
def doh_rejects_malformed_dns():
    check_invalid_dns("doh", True)


@case
def dot_rejects_malformed_dns():
    check_invalid_dns("dot", True)


@case
def doh_rejects_mismatched_dns_id():
    check_invalid_dns("doh", False)


@case
def dot_rejects_mismatched_dns_id():
    check_invalid_dns("dot", False)


def check_shared_deadline(transport):
    def handler(server, stream, request):
        if server.stop.wait(0.5):
            return
        answer_handler()(server, stream, request)
    with TlsServer(transport, handler, handshake_delay=0.4,
                   permit_disconnect=True) as server:
        result = invoke(server, timeout=800)
    check_failure(result, "timeout")
    check_request(server)


@case
def doh_handshake_and_http_share_deadline():
    check_shared_deadline("doh")


@case
def dot_handshake_and_dns_share_deadline():
    check_shared_deadline("dot")


@case
def encrypted_queries_ignore_proxy_environment():
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
            raise AssertionError("client contacted an implicit proxy")


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
        parser.error("--executable and --case are required")
    EXECUTABLE = args.executable.resolve()
    require(EXECUTABLE.is_file(), f"executable does not exist: {EXECUTABLE}")
    try:
        with crl_server():
            CASES[args.case]()
    except BaseException:
        traceback.print_exc()
        return 1
    print(f"PASS {args.case}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
