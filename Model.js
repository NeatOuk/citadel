// Pure helpers for Citadel's service and views: rule matching, the
// nftables spec builder, alert keys and formatting. No QML or file I/O here,
// so the logic can be unit-tested with node (see tests/model.test.js).

// ------------------------------------------------------------------ formatting

function humanBytes(n) {
  var v = Number(n)
  if (!isFinite(v) || v <= 0) return "0 B"
  var units = ["B", "KB", "MB", "GB", "TB"]
  var u = 0
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++ }
  return (v >= 100 || u === 0 ? Math.round(v) : v.toFixed(1)) + " " + units[u]
}

function humanRate(bytesPerSec) {
  return humanBytes(bytesPerSec) + "/s"
}

function clock(ts) {
  var d = new Date((ts || Date.now() / 1000) * 1000)
  function pad(x) { return x < 10 ? "0" + x : String(x) }
  return pad(d.getHours()) + ":" + pad(d.getMinutes())
}

function ago(ts, now) {
  var s = Math.max(0, Math.round((now || Date.now() / 1000) - ts))
  if (s < 60) return s + "s ago"
  if (s < 3600) return Math.round(s / 60) + "m ago"
  if (s < 86400) return Math.round(s / 3600) + "h ago"
  return Math.round(s / 86400) + "d ago"
}

// Regional-indicator flag for an ISO country code ("DE" -> 🇩🇪).
function flag(cc) {
  var s = String(cc || "").toUpperCase()
  if (!/^[A-Z]{2}$/.test(s)) return ""
  return String.fromCodePoint(0x1F1E6 + s.charCodeAt(0) - 65, 0x1F1E6 + s.charCodeAt(1) - 65)
}

var PORT_NAMES = { 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 123: "ntp", 443: "https",
                   465: "smtps", 587: "smtp", 853: "dns-tls", 993: "imaps", 5228: "google-push" }
function portName(port) { return PORT_NAMES[Number(port)] || "" }

function appLabel(conn) {
  return conn.app || (conn.exe ? conn.exe.split("/").pop() : "unknown")
}

// "via omarchy-network-speedtest" / "started in ghostty" / ""
function originLabel(conn) {
  if (!conn || !conn.via) return ""
  return conn.viaKind === "terminal" ? "started in " + conn.via : "via " + conn.via
}

function appWithOrigin(conn) {
  var o = conn && conn.via ? (conn.viaKind === "terminal" ? " in " : " via ") + conn.via : ""
  return appLabel(conn) + o
}

function viaLabel(viaId) {
  if (!viaId || viaId === "*") return ""
  return String(viaId).split("/").pop()
}

function destLabel(conn) {
  return conn.host || conn.raddr || "?"
}

// ------------------------------------------------------------------ addresses

function parseIPv4(s) {
  var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s))
  if (!m) return null
  var n = 0
  for (var i = 1; i <= 4; i++) {
    var b = Number(m[i])
    if (b > 255) return null
    n = n * 256 + b
  }
  return n
}

// "1.2.3.0/24" or "1.2.3.4" -> {v:4, net, bits} ; IPv6 literal -> {v:6, text, bits}
function parseNet(s) {
  var str = String(s || "").trim()
  var parts = str.split("/")
  var bits = parts.length > 1 ? Number(parts[1]) : null
  var v4 = parseIPv4(parts[0])
  if (v4 !== null) {
    if (bits === null) bits = 32
    if (!(bits >= 0 && bits <= 32)) return null
    return { v: 4, net: v4, bits: bits }
  }
  if (parts[0].indexOf(":") !== -1 && /^[0-9a-fA-F:.]+$/.test(parts[0])) {
    if (bits === null) bits = 128
    return { v: 6, text: expandIPv6(parts[0]), bits: bits }
  }
  return null
}

function expandIPv6(s) {
  var str = String(s).toLowerCase()
  var halves = str.split("::")
  var head = halves[0] ? halves[0].split(":") : []
  var tail = halves.length > 1 && halves[1] ? halves[1].split(":") : []
  var fill = Math.max(0, 8 - head.length - tail.length)
  var zeros = []
  for (var z = 0; z < fill; z++) zeros.push("0")
  var groups = head.concat(zeros, tail)
  var bin = ""
  for (var i = 0; i < groups.length; i++) {
    var g = parseInt(groups[i] || "0", 16)
    var b = g.toString(2)
    bin += "0000000000000000".slice(b.length) + b
  }
  return bin
}

function isAddressLike(s) { return parseNet(s) !== null }

function netContains(netStr, ip) {
  var n = parseNet(netStr)
  var a = parseNet(ip)
  if (!n || !a || n.v !== a.v) return false
  if (n.v === 4) {
    if (n.bits === 0) return true
    var shift = 32 - n.bits
    return Math.floor(n.net / Math.pow(2, shift)) === Math.floor(a.net / Math.pow(2, shift))
  }
  return n.text.slice(0, n.bits) === a.text.slice(0, n.bits)
}

// ------------------------------------------------------------------ rules

// A rule: { id, profile: "*"|name, app: "*"|exe, via: "*"|launcher id (script
//           path or exe of the process that started the app), host: "*"|hostname|IP|CIDR,
//           port: "*"|number, action: "allow"|"deny",
//           duration: "forever"|"untilQuit", pids: [..] (untilQuit),
//           exeHash, note, createdAt }

function normHost(h) {
  return String(h === undefined || h === null ? "*" : h).trim().toLowerCase().replace(/\.$/, "") || "*"
}

function normPort(p) {
  if (p === undefined || p === null || p === "" || p === "*") return "*"
  var n = Number(p)
  return n >= 1 && n <= 65535 ? Math.round(n) : "*"
}

function makeRule(fields) {
  var f = fields || {}
  return {
    id: f.id || (Date.now().toString(36) + Math.random().toString(36).slice(2, 7)),
    profile: f.profile || "*",
    app: f.app || "*",
    via: f.via || "*",
    host: normHost(f.host),
    port: normPort(f.port),
    action: f.action === "deny" ? "deny" : "allow",
    duration: f.duration === "untilQuit" ? "untilQuit" : "forever",
    pids: f.pids || [],
    exeHash: f.exeHash || "",
    note: f.note || "",
    createdAt: f.createdAt || Math.floor(Date.now() / 1000)
  }
}

// Higher = more specific. app+host beats host-only beats app-only; a port
// narrows any of them. Must match the nft ordering in buildSpec().
function specificity(rule) {
  var app = rule.app && rule.app !== "*"
  var host = rule.host && rule.host !== "*"
  var s = app && host ? 30 : host ? 20 : app ? 10 : 0
  if (rule.port !== "*" && rule.port !== undefined) s += 5
  if (rule.via && rule.via !== "*") s += 3       // "curl, only when started by X"
  return s
}

function hostMatches(ruleHost, conn, resolved) {
  var h = normHost(ruleHost)
  if (h === "*") return true
  if (isAddressLike(h)) return netContains(h, conn.raddr)
  var name = normHost(conn.host)
  if (name !== "*" && (name === h || name.slice(-(h.length + 1)) === "." + h)) return true
  var ips = resolved ? resolved[h] : null
  return !!(ips && ips.indexOf(conn.raddr) !== -1)
}

function ruleActive(rule, ctx) {
  if (rule.profile && rule.profile !== "*" && rule.profile !== ctx.profile) return false
  if (rule.duration === "untilQuit") {
    var alive = ctx.alivePids || {}
    var pids = rule.pids || []
    for (var i = 0; i < pids.length; i++) if (alive[pids[i]]) return true
    return false
  }
  return true
}

function ruleMatches(rule, conn, ctx) {
  if (!ruleActive(rule, ctx)) return false
  if (rule.app && rule.app !== "*" && rule.app !== conn.exe) return false
  if (rule.via && rule.via !== "*" && rule.via !== (conn.viaId || "")) return false
  if (rule.port !== "*" && rule.port !== undefined && Number(rule.port) !== Number(conn.rport)) return false
  return hostMatches(rule.host, conn, ctx.resolved)
}

// Best matching rule for a connection, or null. Deny wins ties.
function bestRule(conn, rules, ctx) {
  var best = null, bestScore = -1
  for (var i = 0; i < (rules || []).length; i++) {
    var r = rules[i]
    if (!ruleMatches(r, conn, ctx)) continue
    var score = specificity(r) * 2 + (r.action === "deny" ? 1 : 0)
    if (score > bestScore) { best = r; bestScore = score }
  }
  return best
}

// ctx: { profile, mode: "guarded"|"open"|"lockdown", resolved,
//        alivePids, session: {alertKey: "allow"|"deny"} }
// -> { verdict: "allow"|"deny"|"prompt"|"system", source, rule }
function decide(conn, rules, ctx) {
  if (conn.system) return { verdict: "system", source: "system", rule: null }
  var r = bestRule(conn, rules, ctx)
  if (r) return { verdict: r.action, source: "rule", rule: r }
  if (conn.list) return { verdict: "deny", source: "blocklist", rule: null, list: conn.list }
  var s = ctx.session ? ctx.session[alertKey(conn)] : null
  if (s) return { verdict: s, source: "once", rule: null }
  if (ctx.mode === "open") return { verdict: "allow", source: "silent", rule: null }
  if (ctx.mode === "lockdown") return { verdict: "deny", source: "silent", rule: null }
  return { verdict: "prompt", source: "none", rule: null }
}

// Alerts are per app + destination + port, not per socket.
function alertKey(conn) {
  return [conn.exe || conn.app || "?", conn.viaId || "",
          normHost(conn.host) !== "*" ? normHost(conn.host) : conn.raddr, conn.rport || 0].join("|")
}

// Rule fields for an alert answer. scope: "hostPort" | "host" | "app"
function ruleFromAlert(alert, action, scope, duration, profile, appInfo, viaScoped) {
  var conn = alert.conn
  var host = conn.host || conn.raddr
  return makeRule({
    profile: profile || "*",
    app: conn.exe || "*",
    via: viaScoped && conn.viaId ? conn.viaId : "*",
    host: scope === "app" ? "*" : host,
    port: scope === "hostPort" ? conn.rport : "*",
    action: action,
    duration: duration === "untilQuit" ? "untilQuit" : "forever",
    pids: duration === "untilQuit" && appInfo ? appInfo.pids || [] : [],
    exeHash: appInfo && appInfo.trust ? appInfo.trust.hash || "" : ""
  })
}

// ------------------------------------------------------------------ nft spec

function uniq(arr) {
  var seen = {}, out = []
  for (var i = 0; i < arr.length; i++) {
    var k = typeof arr[i] === "string" ? arr[i] : JSON.stringify(arr[i])
    if (!seen[k]) { seen[k] = true; out.push(arr[i]) }
  }
  return out
}

// Destination IPs a rule's host means right now: resolved addresses, live
// matching connections, and IPs learned earlier (so the set only grows and
// the firewall isn't reloaded every time a connection closes).
function hostTargets(rule, conns, resolved, learned) {
  var h = normHost(rule.host)
  var port = rule.port === "*" ? null : rule.port
  var ips = []
  if (isAddressLike(h)) ips.push(h)
  else {
    var r = resolved ? resolved[h] : null
    if (r) ips = ips.concat(r)
    for (var i = 0; i < conns.length; i++)
      if (!conns[i].system && hostMatches(h, conns[i], null)) ips.push(conns[i].raddr)
    if (learned && learned[rule.id]) ips = ips.concat(learned[rule.id])
  }
  return uniq(ips).sort().map(function(ip) { return { ip: ip, port: port } })
}

// Remember which IPs each rule has matched (ruleId -> {ip: lastSeen}).
// Host rules learn matching destinations; whole-app rules learn the app's
// destinations (used when the app shares a cgroup). Entries expire after ttl.
function learnTargets(learned, rules, conns, now, ttl) {
  var out = {}
  var limit = now - (ttl || 3600)
  for (var id in learned) {
    var m = {}, any = false
    for (var ip in learned[id]) if (learned[id][ip] >= limit) { m[ip] = learned[id][ip]; any = true }
    if (any) out[id] = m
  }
  for (var i = 0; i < rules.length; i++) {
    var r = rules[i]
    var named = r.host !== "*" && !isAddressLike(r.host)
    var wholeApp = r.app !== "*" && r.host === "*"
    var viaRule = r.via && r.via !== "*"
    if (!named && !wholeApp && !viaRule) continue
    for (var j = 0; j < conns.length; j++) {
      var c = conns[j]
      if (c.system) continue
      var hit
      if (viaRule) hit = c.exe === r.app && (c.viaId || "") === r.via && hostMatches(r.host, c, null)
      else hit = named ? hostMatches(r.host, c, null) : c.exe === r.app
      if (!hit) continue
      if (!out[r.id]) out[r.id] = {}
      if (named || wholeApp) out[r.id][c.raddr] = now
      if (viaRule && c.cgroup) out[r.id]["cg:" + c.cgroup] = now
    }
  }
  return out
}

function learnedIps(learned) {
  var out = {}
  for (var id in learned) out[id] = Object.keys(learned[id]).filter(function(k) { return k.indexOf("cg:") !== 0 })
  return out
}

function learnedCgroups(learned) {
  var out = {}
  for (var id in learned)
    out[id] = Object.keys(learned[id]).filter(function(k) { return k.indexOf("cg:") === 0 }).map(function(k) { return k.slice(3) })
  return out
}

function userCgroup(cg, uid) {
  return String(cg || "").indexOf("user.slice/user-" + uid + ".slice/") === 0
}

// Build the ordered spec that ls-enforcer turns into nftables rules.
// Returns { spec, approx: {ruleId: true} } — approx marks app rules that can
// only be enforced per destination because the app shares its cgroup.
function buildSpec(rules, ctx, conns, apps, blocklistCidrs, uid) {
  var entries = []
  var approx = {}
  var active = (rules || []).filter(function(r) { return ruleActive(r, ctx) })
  // most specific first; deny before allow at equal specificity
  active.sort(function(a, b) {
    var d = specificity(b) - specificity(a)
    if (d !== 0) return d
    return (a.action === "deny" ? 0 : 1) - (b.action === "deny" ? 0 : 1)
  })
  var blocklistPlaced = false
  for (var i = 0; i < active.length; i++) {
    var r = active[i]
    var verdict = r.action === "deny" ? "drop" : "accept"
    var hasApp = r.app && r.app !== "*"
    var hasHost = r.host && r.host !== "*"
    // blocklists sit between host rules and app-only rules
    if (!blocklistPlaced && !hasHost && hasApp) { entries.push({ blocklist: true }); blocklistPlaced = true }
    if (!hasApp) {
      var t = hostTargets(r, conns, ctx.resolved, ctx.learned)
      if (t.length) entries.push({ verdict: verdict, targets: t })
      continue
    }
    if (r.via && r.via !== "*") {
      // The launcher's cgroup also holds the launcher itself, so a "via" rule
      // can only be enforced per destination inside that cgroup.
      approx[r.id] = true
      var cgs = uniq(conns.filter(function(c) { return !c.system && c.exe === r.app && (c.viaId || "") === r.via })
        .map(function(c) { return c.cgroup })
        .concat(ctx.learnedCg && ctx.learnedCg[r.id] ? ctx.learnedCg[r.id] : []))
        .filter(function(c) { return userCgroup(c, uid) }).sort()
      var vt = hasHost ? hostTargets(r, conns, ctx.resolved, ctx.learned)
        : uniq(conns.filter(function(c) { return c.exe === r.app && (c.viaId || "") === r.via }).map(function(c) { return c.raddr })
            .concat(ctx.learned && ctx.learned[r.id] ? ctx.learned[r.id] : [])).sort()
            .map(function(ip) { return { ip: ip, port: r.port === "*" ? null : r.port } })
      if (vt.length) for (var v = 0; v < cgs.length; v++) entries.push({ verdict: verdict, cgroup: cgs[v], targets: vt })
      continue
    }
    var info = apps ? apps[r.app] : null
    if (!info) continue                          // app not running
    var owned = (info.owned || []).filter(function(c) { return userCgroup(c, uid) })
    var all = (info.cgroups || []).filter(function(c) { return userCgroup(c, uid) })
    if (hasHost) {
      var tg = hostTargets(r, conns, ctx.resolved, ctx.learned)
      if (!tg.length) continue
      for (var a = 0; a < all.length; a++) entries.push({ verdict: verdict, cgroup: all[a], targets: tg })
      if (all.length > owned.length) approx[r.id] = true
      continue
    }
    // whole app
    for (var o = 0; o < owned.length; o++) entries.push({ verdict: verdict, cgroup: owned[o] })
    var shared = all.filter(function(c) { return owned.indexOf(c) === -1 })
    if (shared.length) {
      approx[r.id] = true
      // shared cgroup (e.g. a CLI inside a terminal): limit to what this app
      // is talking to, inside that cgroup only
      var dests = uniq(conns.filter(function(c) { return c.exe === r.app }).map(function(c) { return c.raddr })
        .concat(ctx.learned && ctx.learned[r.id] ? ctx.learned[r.id] : [])).sort()
      var port = r.port === "*" ? null : r.port
      if (dests.length) {
        for (var s = 0; s < shared.length; s++)
          entries.push({ verdict: verdict, cgroup: shared[s],
                         targets: dests.map(function(ip) { return { ip: ip, port: port } }) })
      }
    }
  }
  if (!blocklistPlaced) entries.push({ blocklist: true })
  return {
    spec: { silentDeny: ctx.mode === "lockdown", blocklist: blocklistCidrs || [], rules: entries },
    approx: approx
  }
}

// Live sockets to tear down after a deny: [{cgroup, ip}]
function killTargets(conns, pred, uid) {
  var out = []
  for (var i = 0; i < conns.length; i++) {
    var c = conns[i]
    if (c.system || !userCgroup(c.cgroup, uid)) continue
    if (pred(c)) out.push({ cgroup: c.cgroup, ip: c.raddr })
  }
  return uniq(out)
}

// ------------------------------------------------------------------ profiles

function activeProfile(profiles, override, networkNames) {
  if (override) {
    for (var i = 0; i < profiles.length; i++) if (profiles[i].name === override) return override
  }
  var names = networkNames || []
  for (var j = 0; j < profiles.length; j++) {
    var nets = profiles[j].networks || []
    for (var k = 0; k < nets.length; k++) if (names.indexOf(nets[k]) !== -1) return profiles[j].name
  }
  return profiles.length ? profiles[0].name : "Default"
}

// ------------------------------------------------------------------ helper gate

function versionLess(a, b) {
  var x = String(a).split("."), y = String(b).split(".")
  for (var i = 0; i < 3; i++) {
    var d = (Number(x[i]) || 0) - (Number(y[i]) || 0)
    if (d !== 0) return d < 0
  }
  return false
}

// May the plugin send privileged requests (apply / kill) to the helper?
// Only once its version is known and at least `min`: older helpers have a
// kill path that can close other users' sockets. ("off" is always allowed.)
// Unreleased builds that still had the kill bug.
var BAD_HELPERS = ["1.2.0"]

function helperGate(installed, version, min) {
  if (!installed) return { usable: false, reason: "missing" }
  if (!version) return { usable: false, reason: "checking" }
  if (versionLess(version, min) || BAD_HELPERS.indexOf(String(version)) !== -1) return { usable: false, reason: "outdated" }
  return { usable: true, reason: "" }
}

// ------------------------------------------------------------------ grouping

// conns -> [{app, exe, conns, up, down, upRate, downRate, verdicts}], busiest first
function groupByApp(conns, decisions) {
  var by = {}
  for (var i = 0; i < conns.length; i++) {
    var c = conns[i]
    var k = c.system ? "system:" + c.app : (c.exe || c.app) + (c.viaId ? "|" + c.viaId : "")
    var g = by[k] || { key: k, app: c.app, exe: c.exe, system: !!c.system, conns: [],
                       via: c.via || "", viaId: c.viaId || "", viaKind: c.viaKind || "",
                       up: 0, down: 0, upRate: 0, downRate: 0, denied: 0, prompts: 0 }
    g.conns.push(c)
    g.up += c.up || 0; g.down += c.down || 0
    g.upRate += c.upRate || 0; g.downRate += c.downRate || 0
    var d = decisions ? decisions[c.key] : null
    if (d && d.verdict === "deny") g.denied++
    if (d && d.verdict === "prompt") g.prompts++
    by[k] = g
  }
  var list = Object.keys(by).map(function(k) { return by[k] })
  list.sort(function(a, b) {
    if (a.system !== b.system) return a.system ? 1 : -1
    return (b.upRate + b.downRate) - (a.upRate + a.downRate) || (b.up + b.down) - (a.up + a.down)
  })
  return list
}
