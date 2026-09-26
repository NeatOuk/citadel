// Run: node tests/model.test.js
const fs = require("fs"), vm = require("vm"), path = require("path")
const ctxObj = {}
vm.createContext(ctxObj)
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "Model.js"), "utf8"), ctxObj)
const M = ctxObj
let fails = 0, n = 0
function eq(name, got, want) {
  n++
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { fails++; console.log("FAIL", name, "\n  got ", g, "\n  want", w) }
}
const CH = "/usr/lib/chromium/chromium", CURL = "/usr/bin/curl"
const CGC = "user.slice/user-1000.slice/user@1000.service/app.slice/app-chromium.scope"
const CGT = "user.slice/user-1000.slice/user@1000.service/app.slice/app-term.scope"
const conn = (o) => Object.assign({ key: Math.random() + "", proto: "tcp", exe: CH, app: "chromium",
  raddr: "142.250.1.1", rport: 443, host: "www.google.com", cgroup: CGC, system: false }, o)
const ctx = (o) => Object.assign({ profile: "Home", mode: "guarded", resolved: {}, alivePids: {}, session: {} }, o)

// addresses
eq("v4 in cidr", M.netContains("10.0.0.0/8", "10.2.3.4"), true)
eq("v4 not in cidr", M.netContains("10.0.0.0/8", "11.2.3.4"), false)
eq("v4 exact", M.netContains("1.1.1.1", "1.1.1.1"), true)
eq("v6 in prefix", M.netContains("2606:4700::/32", "2606:4700:10::6814:179a"), true)
eq("v6 not in prefix", M.netContains("2606:4700::/32", "2607:f8b0::1"), false)
eq("bad", M.isAddressLike("example.com"), false)
eq("flag", M.flag("de"), "🇩🇪")

// matching + precedence
const allowApp = M.makeRule({ app: CH, action: "allow" })
const denyHost = M.makeRule({ host: "google.com", action: "deny" })
eq("host rule beats app rule", M.decide(conn(), [allowApp, denyHost], ctx()).verdict, "deny")
const allowAppHost = M.makeRule({ app: CH, host: "google.com", action: "allow" })
eq("app+host beats host", M.decide(conn(), [allowApp, denyHost, allowAppHost], ctx()).verdict, "allow")
const denyAppHostPort = M.makeRule({ app: CH, host: "google.com", port: 443, action: "deny" })
eq("port narrows", M.decide(conn(), [allowAppHost, denyAppHostPort], ctx()).verdict, "deny")
eq("port mismatch falls back", M.decide(conn({ rport: 80 }), [allowAppHost, denyAppHostPort], ctx()).verdict, "allow")
const allowSame = M.makeRule({ app: CH, host: "google.com", action: "allow" })
const denySame = M.makeRule({ app: CH, host: "google.com", action: "deny" })
eq("deny wins ties", M.decide(conn(), [allowSame, denySame], ctx()).verdict, "deny")
eq("subdomain match", M.hostMatches("google.com", conn({ host: "mail.google.com" }), {}), true)
eq("no suffix trick", M.hostMatches("gle.com", conn({ host: "google.com" }), {}), false)
eq("resolved ip match", M.hostMatches("example.com", conn({ host: "", raddr: "1.2.3.4" }), { "example.com": ["1.2.3.4"] }), true)
eq("cidr rule", M.decide(conn({ raddr: "10.1.2.3" }), [M.makeRule({ host: "10.0.0.0/8", action: "deny" })], ctx()).verdict, "deny")
eq("other app not matched", M.decide(conn({ exe: CURL }), [M.makeRule({ app: CH, action: "deny" })], ctx()).verdict, "prompt")
eq("profile filter", M.decide(conn(), [M.makeRule({ app: CH, action: "deny", profile: "Work" })], ctx()).verdict, "prompt")
eq("profile all", M.decide(conn(), [M.makeRule({ app: CH, action: "deny", profile: "*" })], ctx()).verdict, "deny")
const uq = M.makeRule({ app: CH, action: "deny", duration: "untilQuit", pids: [42] })
eq("untilQuit alive", M.decide(conn(), [uq], ctx({ alivePids: { 42: true } })).verdict, "deny")
eq("untilQuit dead", M.decide(conn(), [uq], ctx()).verdict, "prompt")
eq("system never filtered", M.decide(conn({ system: true }), [M.makeRule({ host: "google.com", action: "deny" })], ctx()).verdict, "system")
eq("blocklist", M.decide(conn({ list: "stevenblack" }), [], ctx()).verdict, "deny")
eq("explicit allow beats blocklist", M.decide(conn({ list: "x" }), [allowAppHost], ctx()).verdict, "allow")
eq("silent allow", M.decide(conn(), [], ctx({ mode: "open" })).source, "silent")
eq("silent deny", M.decide(conn(), [], ctx({ mode: "lockdown" })).verdict, "deny")
const c1 = conn()
eq("session once", M.decide(c1, [], ctx({ session: { [M.alertKey(c1)]: "allow" } })).verdict, "allow")

// spec
const apps = { [CH]: { pids: [1], cgroups: [CGC], owned: [CGC] },
               [CURL]: { pids: [2], cgroups: [CGT], owned: [] } }
const conns = [conn(), conn({ exe: CURL, app: "curl", raddr: "93.184.216.34", host: "example.com", cgroup: CGT })]
const rules = [
  M.makeRule({ app: CH, action: "deny" }),                                   // whole app, owned cgroup
  M.makeRule({ app: CURL, action: "deny" }),                                 // shared cgroup -> approx
  M.makeRule({ host: "example.com", action: "allow" }),                      // host
  M.makeRule({ app: CH, host: "www.google.com", port: 443, action: "allow" }), // app+host+port
  M.makeRule({ app: "/usr/bin/notrunning", action: "deny" }),
]
const res = M.buildSpec(rules, ctx({ resolved: { "example.com": ["93.184.216.34", "2606:2800::1"] } }), conns, apps, ["5.188.10.0/23"], 1000)
eq("spec order", res.spec.rules.map(e => e.blocklist ? "BL" : e.verdict + (e.cgroup ? ":cg" : "") + (e.targets ? ":" + e.targets.length : "")),
   ["accept:cg:1", "accept:2", "BL", "drop:cg", "drop:cg:1"])
eq("app+host target has port", res.spec.rules[0].targets[0], { ip: "142.250.1.1", port: 443 })
eq("approx marked for shared cgroup", Object.keys(res.approx).length, 1)
eq("silentDeny flag", M.buildSpec([], ctx({ mode: "lockdown" }), [], {}, [], 1000).spec.silentDeny, true)
eq("foreign cgroup ignored", M.buildSpec([M.makeRule({ app: "/x", action: "deny" })], ctx(), [],
   { "/x": { cgroups: ["system.slice/foo.service"], owned: ["system.slice/foo.service"] } }, [], 1000).spec.rules, [{ blocklist: true }])
eq("kill targets", M.killTargets(conns, c => c.exe === CH, 1000), [{ cgroup: CGC, ip: "142.250.1.1" }])

// learned targets keep IPs after connections close, and expire
const hr = M.makeRule({ id: "h1", host: "google.com", action: "deny" })
let L = M.learnTargets({}, [hr], [conn({ raddr: "1.2.3.4", host: "www.google.com" })], 1000, 3600)
L = M.learnTargets(L, [hr], [], 2000, 3600)
eq("learned kept", M.learnedIps(L), { h1: ["1.2.3.4"] })
eq("learned in spec", M.buildSpec([hr], ctx({ learned: M.learnedIps(L) }), [], {}, [], 1000).spec.rules[0].targets, [{ ip: "1.2.3.4", port: null }])
eq("learned expires", M.learnedIps(M.learnTargets(L, [hr], [], 5000, 3600)), {})

// profiles
const profiles = [{ name: "Home", networks: ["US"] }, { name: "Public", networks: ["Cafe WiFi"] }]
eq("profile by ssid", M.activeProfile(profiles, "", ["Cafe WiFi"]), "Public")
eq("profile default", M.activeProfile(profiles, "", ["Unknown"]), "Home")
eq("profile override", M.activeProfile(profiles, "Public", ["US"]), "Public")

console.log(`${n - fails}/${n} passed`)
process.exit(fails ? 1 : 0)
