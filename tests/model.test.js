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

// origin ("via")
const SPEED = "/usr/share/omarchy/bin/omarchy-network-speedtest"
const CURLC = (o) => conn(Object.assign({ exe: CURL, app: "curl", host: "x.nflxvideo.net", raddr: "23.246.54.150",
  cgroup: CGT, via: "omarchy-network-speedtest", viaId: SPEED, viaKind: "script" }, o))
const viaAllow = M.makeRule({ app: CURL, via: SPEED, action: "allow" })
eq("via rule matches its launcher", M.decide(CURLC(), [viaAllow], ctx()).verdict, "allow")
eq("via rule ignores other launchers", M.decide(CURLC({ viaId: "/home/me/other.sh", via: "other.sh" }), [viaAllow], ctx()).verdict, "prompt")
eq("via beats plain app rule", M.decide(CURLC(), [M.makeRule({ app: CURL, action: "deny" }), viaAllow], ctx()).verdict, "allow")
eq("alert key splits launchers", M.alertKey(CURLC()) !== M.alertKey(CURLC({ viaId: "/x/y" })), true)
eq("ruleFromAlert via scoped", M.ruleFromAlert({ conn: CURLC() }, "allow", "host", "forever", "*", null, true).via, SPEED)
eq("ruleFromAlert any launcher", M.ruleFromAlert({ conn: CURLC() }, "allow", "host", "forever", "*", null, false).via, "*")
const viaDeny = M.makeRule({ id: "v1", app: CURL, via: SPEED, action: "deny" })
const vs = M.buildSpec([viaDeny], ctx(), [CURLC()], {}, [], 1000)
const firstCg = (spec) => spec.rules.filter(e => e.cgroup)[0]
eq("via rule enforced per destination in launcher cgroup", firstCg(vs.spec), { verdict: "drop", cgroup: CGT, targets: [{ ip: "23.246.54.150", port: null }] })
eq("via rule marked approximate", vs.approx.v1, true)
const LV = M.learnTargets({}, [viaDeny], [CURLC()], 1000, 3600)
eq("learned via cgroup", M.learnedCgroups(LV).v1, [CGT])
eq("learned via ip", M.learnedIps(LV).v1, ["23.246.54.150"])
const vs2 = M.buildSpec([viaDeny], ctx({ learned: M.learnedIps(LV), learnedCg: M.learnedCgroups(LV) }), [], {}, [], 1000)
eq("via rule survives after curl exits", (firstCg(vs2.spec) || {}).cgroup, CGT)
eq("grouping splits launchers", M.groupByApp([CURLC(), CURLC({ viaId: "/x/y", via: "y" })], {}).length, 2)
eq("origin label", M.originLabel(CURLC()), "via omarchy-network-speedtest")
eq("terminal label", M.originLabel(CURLC({ via: "ghostty", viaKind: "terminal" })), "started in ghostty")
// helper gate: no privileged requests to helpers older than 1.1.1
eq("gate: missing", M.helperGate(false, "", "1.1.1"), { usable: false, reason: "missing" })
eq("gate: version unknown yet", M.helperGate(true, "", "1.1.1"), { usable: false, reason: "checking" })
eq("gate: pre-1.1.1 (no version = 1.1.0)", M.helperGate(true, "1.1.0", "1.1.1").usable, false)
eq("gate: outdated reason", M.helperGate(true, "1.0.9", "1.1.1").reason, "outdated")
eq("gate: 1.1.1 ok", M.helperGate(true, "1.1.1", "1.1.1").usable, true)
eq("gate: 1.2.1 ok", M.helperGate(true, "1.2.1", "1.1.1").usable, true)
eq("gate: unreleased 1.2.0 refused", M.helperGate(true, "1.2.0", "1.1.1").usable, false)
eq("gate: 1.10.0 ok", M.helperGate(true, "1.10.0", "1.1.1").usable, true)

// whole-app policy on one port matches only that port (was: every port)
const onPort = M.buildSpec([M.makeRule({ app: CH, port: 443, action: "deny" })], ctx(), [], apps, [], 1000)
eq("whole app + port keeps the port", onPort.spec.rules.filter(e => e.cgroup)[0].targets,
   [{ ip: "0.0.0.0/0", port: 443 }, { ip: "::/0", port: 443 }])

// proxy routes on policies
const PX = [{ id: "p1", name: "Office", type: "http", host: "172.16.1.3", port: 8080, listen: 47001 },
            { id: "p2", name: "Home", type: "socks5", host: "proxy.example", port: 1080, listen: 47002 }]
const allowViaP1 = M.makeRule({ id: "a1", app: CH, action: "allow", route: "p1" })
eq("routes default to 'default'", M.makeRule({ app: CH, action: "allow" }).route, "default")
eq("old policies load with the default route", M.makeRule({ id: "old", app: CH, action: "allow", createdAt: 1 }).route, "default")
let rt = M.compileRoutes([allowViaP1], "direct", PX, ctx({ resolved: { "proxy.example": ["203.0.113.7"] } }), [], apps, 1000)
eq("allow via proxy redirects the app to its listener", rt.rules, [{ verdict: "redirect", port: 47001, cgroup: CGC }])
eq("default direct: no catch-all", rt.defaultPort, null)
eq("proxy servers are excluded (literal and resolved)", rt.exclude, ["172.16.1.3", "203.0.113.7"])
eq("nothing routed: no proxy section", M.compileRoutes([M.makeRule({ app: CH, action: "allow" })], "direct", PX, ctx(), [], apps, 1000), null)
rt = M.compileRoutes([M.makeRule({ app: CH, action: "allow" })], "p2", PX, ctx(), [], apps, 1000)
eq("default route via proxy: catch-all", rt.defaultPort, 47002)
eq("a plain Allow leaves routing to the catch-all", rt.rules, [])
rt = M.compileRoutes([allowViaP1, M.makeRule({ app: CH, host: "www.google.com", action: "allow", route: "direct" })],
                     "direct", PX, ctx(), [conn()], apps, 1000)
eq("more specific direct route comes first", rt.rules.map(e => e.verdict), ["direct", "redirect"])
rt = M.compileRoutes([allowViaP1, M.makeRule({ app: CH, host: "www.google.com", action: "deny" })], "direct", PX, ctx(), [conn()], apps, 1000)
eq("block policies are never routed", rt.rules.map(e => e.verdict), ["redirect"])
rt = M.compileRoutes([M.makeRule({ app: CH, action: "allow", route: "gone" })], "direct", PX, ctx(), [], apps, 1000)
eq("route to a deleted proxy fails closed", rt.rules[0].port, 47000)
eq("routeFor: via proxy", M.routeFor(conn(), [allowViaP1], ctx(), "direct", PX).name, "Office")
eq("routeFor: direct", M.routeFor(conn(), [M.makeRule({ app: CH, action: "allow", route: "direct" })], ctx(), "p1", PX), null)
eq("routeFor: no policy uses default", M.routeFor(conn(), [], ctx(), "p2", PX).name, "Home")
eq("routeFor: blocked has no route", M.routeFor(conn(), [M.makeRule({ app: CH, action: "deny" })], ctx(), "p1", PX), null)
// a narrower plain Allow (e.g. from the gate) must not pull a destination out of the app's proxy route
const narrowAllow = M.makeRule({ app: CH, host: "www.google.com", action: "allow" })
rt = M.compileRoutes([allowViaP1, narrowAllow], "direct", PX, ctx(), [conn()], apps, 1000)
eq("plain Allow for a host doesn't override the app's proxy route", rt.rules, [{ verdict: "redirect", port: 47001, cgroup: CGC }])
eq("routeFor: narrower plain Allow keeps the app's proxy", M.routeFor(conn(), [allowViaP1, narrowAllow], ctx(), "direct", PX).name, "Office")
eq("routeFor: narrower explicit direct wins", M.routeFor(conn(), [allowViaP1, M.makeRule({ app: CH, host: "www.google.com", action: "allow", route: "direct" })], ctx(), "direct", PX), null)
eq("routeFor: a Block still wins over the route", M.routeFor(conn(), [allowViaP1, M.makeRule({ app: CH, host: "www.google.com", action: "deny" })], ctx(), "direct", PX), null)
// cutting connections whose route changed
{
  const live = [Object.assign(conn(), { proto: "tcp", raddr: "142.250.1.1", rport: 443 }),
                Object.assign(conn(), { key: "k2", proto: "tcp", raddr: "172.16.1.3", rport: 8080 }),
                Object.assign(conn(), { key: "k3", proto: "udp", raddr: "8.8.8.8", rport: 53 })]
  const routes = M.compileRoutes([allowViaP1], "direct", PX, ctx(), live, apps, 1000)
  eq("route cut: newly routed app's connections are cut, not the proxy's or UDP",
     M.routeCutTargets(null, routes, live, 1000), [{ cgroup: CGC, ip: "142.250.1.1" }])
  eq("route cut: nothing changed, nothing cut", M.routeCutTargets(routes, routes, live, 1000), [])
  eq("route cut: route removed moves traffic back", M.routeCutTargets(routes, null, live, 1000), [{ cgroup: CGC, ip: "142.250.1.1" }])
  const narrow = { rules: [{ verdict: "redirect", port: 47001, cgroup: CGC, targets: [{ ip: "10.0.0.0/8", port: null }] }], exclude: [] }
  eq("route cut: per-destination entry cuts only those destinations", M.routeCutTargets(null, narrow, live, 1000), [])
}
eq("gate: always allow via proxy", M.ruleFromAlert({ conn: conn() }, "allow", "host", "forever", "*", null, false, "p1").route, "p1")
eq("gate: block ignores route", M.ruleFromAlert({ conn: conn() }, "deny", "host", "forever", "*", null, false, "p1").route, "default")
eq("free listener port", M.freeListenPort(PX), 47003)

// profiles
const profiles = [{ name: "Home", networks: ["US"] }, { name: "Public", networks: ["Cafe WiFi"] }]
eq("profile by ssid", M.activeProfile(profiles, "", ["Cafe WiFi"]), "Public")
eq("profile default", M.activeProfile(profiles, "", ["Unknown"]), "Home")
eq("profile override", M.activeProfile(profiles, "Public", ["US"]), "Public")

// where a policy came from, and the Policies list filter
eq("origin: gate verdict", M.ruleFromAlert({ conn: conn() }, "allow", "host", "forever", "*", null, false).origin, "gate")
eq("origin: form / Traffic default to you", M.makeRule({ app: CH, action: "deny" }).origin, "you")
eq("origin: old gate policy (has exeHash)", M.makeRule({ app: CH, exeHash: "ab12", createdAt: 1 }).origin, "gate")
eq("origin: kept when given", M.makeRule({ app: CH, origin: "gate" }).origin, "gate")
{
  const R = [M.makeRule({ id: "g1", app: CH, host: "ads.example", action: "deny", exeHash: "x", createdAt: 100 }),
             M.makeRule({ id: "y1", app: "/usr/bin/remmina", host: "172.16.1.222", action: "allow", createdAt: 300 }),
             M.makeRule({ id: "y2", app: "/opt/microsoft/msedge/msedge", action: "allow", route: "p1", createdAt: 200 }),
             M.makeRule({ id: "z1", host: "work.example", action: "allow", profile: "Work", createdAt: 400 })]
  const ids = (o) => M.filterRules(R, o, id => id === "p1" ? "Office" : "?").map(r => r.id)
  eq("filter: newest first by default", ids({}), ["z1", "y1", "y2", "g1"])
  eq("filter: added by you", ids({ show: "you" }), ["z1", "y1", "y2"])
  eq("filter: from the gate", ids({ show: "gate" }), ["g1"])
  eq("filter: blocks", ids({ show: "deny" }), ["g1"])
  eq("filter: via proxy", ids({ show: "proxy" }), ["y2"])
  eq("search: app basename", ids({ query: "remmina" }), ["y1"])
  eq("search: host part", ids({ query: "168.1" }), ["y1"])
  eq("search: proxy name", ids({ query: "office" }), ["y2"])
  eq("search: every word must match", ids({ query: "msedge office" }), ["y2"])
  eq("filter: zone keeps all-zone policies", ids({ profile: "Home" }), ["y1", "y2", "g1"])
  eq("sort: precedence puts app+host policies first", ids({ sort: "precedence" }).slice(0, 2).sort(), ["g1", "y1"])
}

// importing AdGuard / Pi-hole / hosts / plain lists
{
  const ag = M.parseImport([
    "! AdGuard rules", "[Adblock Plus 2.0]",
    "||ads.example.com^", "||track.example.net^$important", "@@||good.example.com^",
    "||good.example.com^", "||x.example.org^$client=172.16.1.5", "/ads[0-9]+\\.example/",
    "example.com##.banner", "||1.2.3.4^"].join("\n"))
  eq("adguard: format", ag.format, "adguard")
  eq("adguard: blocks (important ok, IP ok)", ag.block, ["1.2.3.4", "ads.example.com", "track.example.net"])
  eq("adguard: @@ allow wins over a block", ag.allow, ["good.example.com"])
  eq("adguard: skipped", ag.skipped, { regex: 1, options: 1, other: 1 })
  const hosts = M.parseImport("# hosts\n0.0.0.0 a.example.com b.example.com\n127.0.0.1 localhost\n::1 c.example.com")
  eq("hosts: format + domains", [hosts.format, hosts.block], ["hosts", ["a.example.com", "b.example.com", "c.example.com"]])
  const pi = M.parseImport("doubleclick.net\n*.tracker.io\n(\\.|^)ads\\.example\\.com$\n", "allow")
  eq("pi-hole plain list as allow", [pi.format, pi.allow, pi.block], ["domains", ["doubleclick.net", "tracker.io"], []])
  eq("pi-hole regex line skipped", pi.skipped.regex, 1)
  eq("plain list defaults to block", M.parseImport("doubleclick.net").block, ["doubleclick.net"])
  const cj = M.parseImport(JSON.stringify({ version: 2, rules: [{ app: "/usr/bin/curl", action: "deny" }] }))
  eq("citadel json passes through", [cj.format, cj.rules.length], ["citadel", 1])
}

// updates to a new path per version (mise, asdf, nvm, Nix)
{
  const OLD = "/home/u/.local/share/mise/installs/claude/2.1.281/claude"
  const NEW = "/home/u/.local/share/mise/installs/claude/2.1.283/claude"
  eq("family: mise", M.appFamily(NEW), "/home/u/.local/share/mise/installs/claude/*/claude")
  eq("family: nvm v-prefix and rc", M.appFamily("/home/u/.nvm/versions/node/v22.1.0-rc.1/bin/node"), "/home/u/.nvm/versions/node/*/bin/node")
  eq("family: nix store", M.appFamily("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-claude-code-2.1.283/bin/claude"),
     "/nix/store/nix:claude-code/bin/claude")
  eq("family: no version part", M.appFamily("/usr/bin/python3.14"), "")
  const rules = [M.makeRule({ app: OLD, action: "allow", createdAt: 5 }), M.makeRule({ app: CURL, action: "allow" })]
  eq("updated from the old path", M.updatedFrom(NEW, rules), OLD)
  eq("not when the new path has a policy", M.updatedFrom(NEW, rules.concat([M.makeRule({ app: NEW, host: "x.example" })])), "")
  eq("not for another app", M.updatedFrom("/home/u/.local/share/mise/installs/node/26.8.2/bin/node", rules), "")
}

console.log(`${n - fails}/${n} passed`)
process.exit(fails ? 1 : 0)
