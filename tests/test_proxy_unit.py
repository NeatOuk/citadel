#!/usr/bin/env python3
"""Unit tests for bin/citadel-proxy's host-name handling (no network).

Covers the TLS server name and HTTP Host parsing, and the rule that a name
the app sent is used only when it resolves to the original destination.
Run: python3 tests/test_proxy_unit.py
"""
import asyncio
import os
import runpy
import ssl
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
g = runpy.run_path(os.path.join(HERE, "..", "bin", "citadel-proxy"), run_name="citadel_proxy")


def client_hello(name):
    """A real ClientHello from Python's TLS stack."""
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=name)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


class FakeReader:
    def __init__(self, chunks, stall=False):
        self.chunks = list(chunks)
        self.stall = stall

    async def read(self, n):
        if self.chunks:
            return self.chunks.pop(0)
        if self.stall:
            await asyncio.sleep(10)
        return b""


def run(coro):
    return asyncio.run(coro)


def main():
    checks = []
    hello = client_hello("outlook.office.com")
    checks.append(("TLS server name parsed", g["tls_server_name"](hello) == "outlook.office.com"))
    checks.append(("incomplete ClientHello -> None", g["tls_server_name"](hello[:20]) is None))
    checks.append(("not TLS -> None", g["tls_server_name"](b"GET / HTTP/1.1\r\n\r\n") is None))
    checks.append(("HTTP Host parsed", g["http_host"](b"GET / HTTP/1.1\r\nHost: example.com:8080\r\nX: y\r\n\r\n") == "example.com"))

    name, data = run(g["sniff"](FakeReader([hello[:30], hello[30:]])))
    checks.append(("sniff: ClientHello in two reads", name == "outlook.office.com" and data == hello))
    name, data = run(g["sniff"](FakeReader([b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"])))
    checks.append(("sniff: HTTP request", name == "a.example" and data.startswith(b"GET")))
    g["SNIFF_TIMEOUT"] = 0.2
    g["sniff"].__globals__["SNIFF_TIMEOUT"] = 0.2
    name, data = run(g["sniff"](FakeReader([], stall=True)))
    checks.append(("sniff: server-speaks-first protocol times out empty", name is None and data == b""))

    # resolution check, with a fake resolver
    async def fake_getaddrinfo(host, port):
        table = {"outlook.office.com": ["52.96.1.2", "2603:1036::1"], "evil.example": ["6.6.6.6"]}
        if host not in table:
            raise OSError("no such host")
        return [(0, 0, 0, "", (ip, 0)) for ip in table[host]]

    async def verify(name, ip):
        loop = asyncio.get_running_loop()
        loop.getaddrinfo = fake_getaddrinfo
        return await g["verified_name"](name, ip)

    checks.append(("name used when it resolves to the destination", run(verify("outlook.office.com", "52.96.1.2")) == "outlook.office.com"))
    checks.append(("IPv6 destination matched", run(verify("outlook.office.com", "2603:1036::1")) == "outlook.office.com"))
    checks.append(("spoofed name (other IP) is refused", run(verify("evil.example", "52.96.1.2")) is None))
    checks.append(("unresolvable name is refused", run(verify("nope.example", "52.96.1.2")) is None))
    checks.append(("header injection is refused", run(verify("a.example\r\nX-Evil: 1", "52.96.1.2")) is None))
    checks.append(("IP literal is not a name", run(verify("52.96.1.2", "52.96.1.2")) is None))

    failed = 0
    for label, ok in checks:
        if not ok:
            failed += 1
            print("FAIL", label)
    print("%d passed, %d failed" % (len(checks) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
