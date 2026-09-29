#!/usr/bin/env python3
"""Tests for bin/citadel-explain with fake agent binaries on PATH.

Each fake agent answers --help with the flags its adapter needs, records its
argv and prints a canned answer. Nothing real is called.
Run: python3 tests/test_explain.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXPLAIN = os.path.join(HERE, "..", "bin", "citadel-explain")

ANSWER = {"company": "Google", "service": "Google Ads", "purpose": "Showing ads", "category": "ads",
          "risk": "medium", "suggestion": "block", "why": "ad tracking", "confidence": "high"}

FAKE = r'''#!/usr/bin/env python3
import json, os, sys
if sys.argv[1:] == ["--help"]:
    print(os.environ.get("FAKE_HELP", "")); sys.exit(0)
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps({"name": os.path.basename(sys.argv[0]), "argv": sys.argv[1:], "cwd": os.getcwd()}) + "\n")
sys.stdout.write(os.environ["FAKE_OUT"]); sys.exit(int(os.environ.get("FAKE_RC", "0")))
'''

HELPS = {
    "claude": "--print --json-schema --no-session-persistence --model",
    "pi": "--no-session --no-tools --model",
    "codex": "exec --model",
    "opencode": "run --model",
    "gemini": "--prompt --model",
    "crush": "run",
    "copilot": "--prompt --model",
    "cursor-agent": "--print --model",
}


def run(tmp, agent, out, prefs=None, req=None, help_text=None, rc=0, home=None):
    bindir = os.path.join(tmp, "bin")
    os.makedirs(bindir, exist_ok=True)
    for name in HELPS:
        p = os.path.join(bindir, name)
        with open(p, "w") as f:
            f.write(FAKE)
        os.chmod(p, 0o755)
    agent_file = os.path.join(tmp, "agent")
    with open(agent_file, "w") as f:
        f.write(agent + "\n")
    log = os.path.join(tmp, "log.jsonl")
    if os.path.exists(log):
        os.remove(log)
    env = dict(os.environ, PATH=bindir + ":/usr/bin:/bin", HOME=home or os.path.join(tmp, "home"),
               CITADEL_AGENT_FILE=agent_file, CITADEL_EXPLAIN_DB=os.path.join(tmp, "h.db"),
               FAKE_LOG=log, FAKE_OUT=out, FAKE_RC=str(rc),
               FAKE_HELP=HELPS.get(agent, "") if help_text is None else help_text)
    body = req or {"conn": {"app": "Chromium", "exe": "/usr/lib/chromium/chromium", "host": "ad.doubleclick.net",
                            "raddr": "142.250.1.1", "rport": 443, "org": "Google LLC"}, "fresh": True}
    body["prefs"] = prefs or {}
    p = subprocess.run([sys.executable, EXPLAIN], input=json.dumps(body), capture_output=True, text=True, env=env,
                       timeout=30)
    calls = [json.loads(l) for l in open(log)] if os.path.exists(log) else []
    return json.loads(p.stdout.strip().splitlines()[-1]), calls


def main():
    checks = []
    with tempfile.TemporaryDirectory() as tmp:
        # claude: structured_output from the JSON envelope
        env_out = json.dumps({"is_error": False, "result": "", "structured_output": ANSWER,
                              "modelUsage": {"claude-x": {}}})
        r, calls = run(tmp, "claude", env_out)
        a = calls[0]["argv"] if calls else []
        checks += [
            ("claude: answer parsed", r.get("ok") and r["result"]["service"] == "Google Ads"),
            ("claude: one-shot flags", a[:3] == ["-p", "--output-format", "json"] and "--json-schema" in a
             and "--no-session-persistence" in a and a[a.index("--tools") + 1] == ""),
            ("claude: model reported", r.get("model") == "claude-x"),
            ("claude: runs in a temp dir", calls and "citadel-explain-" in calls[0]["cwd"]),
            ("claude: prompt has host and owner", "ad.doubleclick.net" in a[-1] and "Google LLC" in a[-1]),
        ]
        r, calls = run(tmp, "claude", env_out, prefs={"explainModel": "haiku"})
        a = calls[0]["argv"]
        checks.append(("claude: model override", a[a.index("--model") + 1] == "haiku"))
        r, _ = run(tmp, "claude", json.dumps({"is_error": True, "result": "Not logged in"}))
        checks.append(("claude: error surfaced", not r["ok"] and "Not logged in" in r["error"]))

        # text agents: JSON inside prose / code fences
        text = "Sure!\n```json\n" + json.dumps(ANSWER) + "\n```\n"
        want = {"pi": ["-p", "--no-session", "--no-tools"], "codex": ["exec"], "opencode": ["run"],
                "gemini": ["-p"], "crush": ["run"], "copilot": ["-p"], "cursor-agent": ["-p"]}
        for agent, prefix in want.items():
            r, calls = run(tmp, agent, text)
            a = calls[0]["argv"] if calls else []
            checks.append(("%s: flags + parse" % agent, r.get("ok") and a[:len(prefix)] == prefix
                           and r["result"]["category"] == "ads" and r["agent"] == agent))
        r, calls = run(tmp, "pi", text, prefs={"explainModel": "qwen"})
        a = calls[0]["argv"]
        checks.append(("pi: model before prompt", a[a.index("--model") + 1] == "qwen" and "Connection:" in a[-1]))
        r, calls = run(tmp, "crush", text, prefs={"explainModel": "x"})
        checks.append(("crush: no model flag", "--model" not in calls[0]["argv"]))

        # garbage values are normalised
        bad = dict(ANSWER, risk="extreme", category="spyware", suggestion="nuke")
        r, _ = run(tmp, "pi", json.dumps(bad))
        checks.append(("normalises enums", r["result"]["risk"] == "medium" and r["result"]["category"] == "other"
                       and r["result"]["suggestion"] == "either"))
        r, _ = run(tmp, "pi", "I don't know")
        checks.append(("no JSON -> failed", not r["ok"] and r["code"] == "failed"))
        r, _ = run(tmp, "pi", "", rc=3)
        checks.append(("exit code -> failed", not r["ok"] and r["code"] == "failed"))

        # agent selection
        r, _ = run(tmp, "", text)
        checks.append(("no agent -> no-agent", not r["ok"] and r["code"] == "no-agent"))
        r, _ = run(tmp, "grok", text)
        checks.append(("unknown agent -> unsupported", r["code"] == "unsupported" and "grok" in r["error"]))
        r, _ = run(tmp, "pi", text, help_text="--foo")
        checks.append(("missing flags -> unsupported", r["code"] == "unsupported" and "--no-tools" in r["error"]))
        r, calls = run(tmp, "grok", text, prefs={"explainCommand": "pi --custom {prompt} --end"})
        a = calls[0]["argv"] if calls else []
        checks.append(("custom command wins", r.get("ok") and r["agent"] == "custom command" and a[0] == "--custom"
                       and a[-1] == "--end" and "Connection:" in a[1]))
        r, calls = run(tmp, "", text, prefs={"explainCommand": "pi --custom"})
        checks.append(("custom command w/o {prompt} appends it", r.get("ok") and "Connection:" in calls[0]["argv"][-1]))

        # cache
        req = {"conn": {"app": "curl", "exe": "/usr/bin/curl", "host": "a.example.co.uk", "raddr": "1.2.3.4",
                        "rport": 443}}
        r1, c1 = run(tmp, "pi", text, req=dict(req))
        req2 = {"conn": dict(req["conn"], host="b.example.co.uk")}
        r2, c2 = run(tmp, "pi", text, req=req2)
        checks.append(("cache: same domain served from cache", not r1["cached"] and r2["cached"] and not c2))
        r3, c3 = run(tmp, "pi", text, req=dict(req2, fresh=True))
        checks.append(("cache: fresh re-asks", not r3["cached"] and len(c3) == 1))
        r4, c4 = run(tmp, "pi", text, req={"test": True})
        checks.append(("test request bypasses cache", r4.get("ok") and len(c4) == 1))

    failed = 0
    for name, ok in checks:
        if not ok:
            failed += 1
            print("FAIL", name)
    print("%d passed, %d failed" % (len(checks) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
