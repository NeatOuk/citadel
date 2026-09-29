#!/usr/bin/env python3
"""End-to-end test of proxy routing, in a private network namespace.

Pieces: citadel-helper's enforcer builds the nft redirect, bin/citadel-proxy
tunnels through fake SOCKS5 / HTTP-CONNECT proxies (with authentication) to a
fake "internet" server. Checks that routed traffic really goes through the
proxy, that it fails closed when the proxy is down, and that nothing leaks
directly when citadel-proxy itself is not running.

No root needed and the real network is untouched (`unshare -rn`).
The enforcer is taken from $CITADEL_ENFORCER, else ../../citadel-helper/.
Run: python3 tests/test_proxy_e2e.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROXY = os.path.join(HERE, "..", "bin", "citadel-proxy")
ENFORCER = os.environ.get("CITADEL_ENFORCER") or os.path.join(HERE, "..", "..", "citadel-helper", "citadel-enforcer")

# Runs inside the namespace. Everything below is one script so the fake
# servers, the redirector and the client share the namespace.
INNER = r'''
import asyncio, json, os, runpy, socket, struct, subprocess, sys, time, base64
TMP = sys.argv[1]; PROXY = sys.argv[2]; ENFORCER = sys.argv[3]
log = []
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
subprocess.run(["ip", "link", "add", "d0", "type", "dummy"], check=True)
subprocess.run(["ip", "addr", "add", "10.99.0.1/24", "dev", "d0"], check=True)
subprocess.run(["ip", "addr", "add", "10.99.0.2/24", "dev", "d0"], check=True)
# The fake proxies live in this same namespace and run as the same user, so
# their onward connection must not match the routing rule again (a real proxy
# is another machine). They relay to the target's second address 10.99.0.3,
# while logging the destination the client asked for.
subprocess.run(["ip", "addr", "add", "10.99.0.3/24", "dev", "d0"], check=True)
subprocess.run(["ip", "link", "set", "d0", "up"], check=True)

async def target(r, w):                      # the "internet" server
    w.write(b"HELLO-FROM-TARGET"); await w.drain(); w.close()

async def relay(r, w, host, port):
    tr, tw = await asyncio.open_connection("10.99.0.3", port)
    async def p(a, b):
        while d := await a.read(65536):
            b.write(d); await b.drain()
        b.close()
    await asyncio.gather(p(r, tw), p(tr, w))

async def socks5(r, w):                      # fake SOCKS5 proxy, user/pass required
    ver, n = await r.readexactly(2); methods = await r.readexactly(n)
    if 2 not in methods: w.write(b"\x05\xff"); w.close(); return
    w.write(b"\x05\x02"); await w.drain()
    await r.readexactly(1); u = await r.readexactly((await r.readexactly(1))[0]); p = await r.readexactly((await r.readexactly(1))[0])
    if (u, p) != (b"alice", b"s3cret"): w.write(b"\x01\x01"); w.close(); return
    w.write(b"\x01\x00"); await w.drain()
    await r.readexactly(3); atyp = (await r.readexactly(1))[0]
    host = socket.inet_ntoa(await r.readexactly(4)) if atyp == 1 else None
    port = struct.unpack("!H", await r.readexactly(2))[0]
    log.append("socks5 %s:%d" % (host, port))
    w.write(b"\x05\x00\x00\x01" + b"\0" * 6); await w.drain()
    await relay(r, w, host, port)

async def httpconnect(r, w):                 # fake HTTP CONNECT proxy, Basic auth required
    head = (await r.readuntil(b"\r\n\r\n")).decode()
    want = "Proxy-Authorization: Basic " + base64.b64encode(b"alice:s3cret").decode()
    if want not in head: w.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"); w.close(); return
    hostport = head.split()[1]; host, port = hostport.rsplit(":", 1)
    log.append("http %s" % hostport)
    w.write(b"HTTP/1.1 200 Connection established\r\n\r\n"); await w.drain()
    await relay(r, w, host, int(port))

def apply(spec):
    with open(TMP + "/spec.json", "w") as f: json.dump(spec, f)
    g = runpy.run_path(ENFORCER, run_name="enf")
    for fn in ("apply_validated",):
        g[fn].__globals__["STATE_DIR"] = TMP + "/state"; g[fn].__globals__["SAVED_SPEC"] = TMP + "/state/spec.json"
    os.environ["PKEXEC_UID"] = str(os.getuid())     # uid 0 inside the namespace
    sys.argv = ["enf", "apply", TMP + "/spec.json"]
    try: g["main"]()
    except SystemExit as e:
        if e.code: raise

def fetch():
    try:
        s = socket.create_connection(("10.99.0.1", 9000), timeout=5)
        data = s.recv(100); s.close(); return data.decode() or "EMPTY"
    except OSError as e:
        return "FAIL:" + type(e).__name__

def spec(port):
    return {"rules": [], "proxy": {"rules": [{"verdict": "redirect", "targets": [{"ip": "10.99.0.1", "port": 9000}], "port": port}],
                                    "exclude": ["10.99.0.2/32"]}}

async def main():
    results = {}
    t = await asyncio.start_server(target, ["10.99.0.1", "10.99.0.3"], 9000)
    s5 = await asyncio.start_server(socks5, "10.99.0.2", 1080)
    hc = await asyncio.start_server(httpconnect, "10.99.0.2", 3128)
    # HTTPS proxy: the same CONNECT proxy behind TLS, with a throwaway self-signed cert
    import ssl
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=10.99.0.2",
                    "-keyout", TMP + "/k.pem", "-out", TMP + "/c.pem"], check=True, capture_output=True)
    sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH); sctx.load_cert_chain(TMP + "/c.pem", TMP + "/k.pem")
    hs = await asyncio.start_server(httpconnect, "10.99.0.2", 3129, ssl=sctx)
    # citadel-proxy with keyring lookups replaced by a test credential
    wrapper = TMP + "/wrap.py"
    open(wrapper, "w").write("import runpy,sys\ng=runpy.run_path(%r, run_name='cp')\n"
        "g['keyring_credentials'].__globals__['keyring_credentials']=lambda pid: ('alice','s3cret')\n"
        "import asyncio; asyncio.run(g['main']())\n" % PROXY)
    cp = await asyncio.create_subprocess_exec(sys.executable, wrapper, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
    cfg = {"cmd": "config", "checkEvery": 3600, "proxies": [
        {"id": "s5", "name": "S", "type": "socks5", "host": "10.99.0.2", "port": 1080, "listen": 47001, "auth": True},
        {"id": "h", "name": "H", "type": "http", "host": "10.99.0.2", "port": 3128, "listen": 47002, "auth": True},
        {"id": "t", "name": "T", "type": "https", "host": "10.99.0.2", "port": 3129, "listen": 47003, "auth": True, "verifyTls": False}]}
    cp.stdin.write((json.dumps(cfg) + "\n").encode()); await cp.stdin.drain(); await asyncio.sleep(1.0)

    loop = asyncio.get_running_loop()
    results["direct_without_rules"] = await loop.run_in_executor(None, fetch)
    apply(spec(47001))
    results["via_socks5"] = await loop.run_in_executor(None, fetch)
    apply(spec(47002))
    results["via_http"] = await loop.run_in_executor(None, fetch)
    apply(spec(47003))
    before = len(log)
    results["via_https"] = await loop.run_in_executor(None, fetch)
    results["https_log"] = log[before:]
    apply(spec(47002))
    hc.close(); await hc.wait_closed()                 # proxy goes down
    results["http_proxy_down"] = await loop.run_in_executor(None, fetch)
    cp.stdin.close(); await cp.wait()                  # citadel-proxy stops
    results["citadel_proxy_stopped"] = await loop.run_in_executor(None, fetch)
    results["proxy_log"] = log
    out = []
    while True:
        line = await cp.stdout.readline()
        if not line: break
        out.append(json.loads(line))
    results["errors_reported"] = [e for e in out if e.get("type") == "error"]
    print(json.dumps(results))

asyncio.run(main())
'''


def main():
    if not os.path.exists(ENFORCER):
        print("SKIP: citadel-enforcer not found (set CITADEL_ENFORCER)")
        return 0
    if subprocess.run(["unshare", "-rn", "true"]).returncode != 0:
        print("SKIP: unprivileged user namespaces are not available")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        script = os.path.join(tmp, "inner.py")
        with open(script, "w") as f:
            f.write(INNER)
        p = subprocess.run(["unshare", "-rn", sys.executable, script, tmp, PROXY, ENFORCER],
                           capture_output=True, text=True, timeout=120)
        try:
            r = json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            print("FAIL: no result\n", p.stdout[-2000:], p.stderr[-2000:])
            return 1
    checks = [
        ("no rule: goes direct", r["direct_without_rules"] == "HELLO-FROM-TARGET"),
        ("SOCKS5 route delivers", r["via_socks5"] == "HELLO-FROM-TARGET"),
        ("SOCKS5 proxy really carried it", "socks5 10.99.0.1:9000" in r["proxy_log"]),
        ("HTTP CONNECT route delivers", r["via_http"] == "HELLO-FROM-TARGET"),
        ("HTTP proxy really carried it", "http 10.99.0.1:9000" in r["proxy_log"]),
        ("HTTPS (TLS) proxy route delivers", r["via_https"] == "HELLO-FROM-TARGET"),
        ("HTTPS proxy really carried it", "http 10.99.0.1:9000" in r["https_log"]),
        ("proxy down: fails closed, no direct leak", r["http_proxy_down"] != "HELLO-FROM-TARGET"),
        ("proxy down: error reported", any(e.get("id") == "h" for e in r["errors_reported"])),
        ("citadel-proxy stopped: fails closed", r["citadel_proxy_stopped"].startswith("FAIL")),
    ]
    failed = 0
    for name, ok in checks:
        if not ok:
            failed += 1
            print("FAIL", name, json.dumps(r)[:600])
    print("%d passed, %d failed" % (len(checks) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
