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
    // allow policies only: "default" (follow the default route), "direct",
    // or a proxy id
    route: f.route && f.route !== "" ? String(f.route) : "default",
    duration: f.duration === "untilQuit" ? "untilQuit" : "forever",
    pids: f.pids || [],
    exeHash: f.exeHash || "",
    note: f.note || "",
    // who made it: "gate" (a verdict at the gate) or "you" (the policy form,
    // Traffic, import). Older policies have none: only gate verdicts store
    // the program's hash, so that tells them apart.
    origin: f.origin === "gate" || f.origin === "you" ? f.origin : (f.exeHash ? "gate" : "you"),
    createdAt: f.createdAt || Math.floor(Date.now() / 1000)
  }
}

// The Policies list: search, "show" filter, zone and sort.
// opts: {query, show: all|you|gate|deny|proxy, sort: newest|precedence, profile: "*all*"|name}
function filterRules(rules, opts, proxyName) {
  var o = opts || {}
  var q = String(o.query || "").trim().toLowerCase()
  var out = (rules || []).filter(function(r) {
    if (o.profile && o.profile !== "*all*" && r.profile !== o.profile && r.profile !== "*") return false
    var routed = r.action === "allow" && r.route && r.route !== "default" && r.route !== "direct"
    if (o.show === "you" && r.origin !== "you") return false
    if (o.show === "gate" && r.origin !== "gate") return false
    if (o.show === "deny" && r.action !== "deny") return false
    if (o.show === "proxy" && !routed) return false
    if (!q) return true
    var hay = [r.app, r.app.split("/").pop(), r.via && r.via !== "*" ? r.via + " " + viaLabel(r.via) : "",
               r.host, String(r.port), routed && proxyName ? proxyName(r.route) : "", r.note || ""]
      .join(" ").toLowerCase()
    return q.split(/\s+/).every(function(w) { return hay.indexOf(w) !== -1 })
  })
  return out.slice().sort(o.sort === "precedence"
    ? function(a, b) { return specificity(b) - specificity(a) || b.createdAt - a.createdAt }
    : function(a, b) { return b.createdAt - a.createdAt })
}

// ------------------------------------------------------------------ import
// Policies from other tools: AdGuard / AdGuard Home rules, Pi-hole lists,
// hosts files, plain domain lists, and Citadel's own JSON export.
//   -> {format, rules (Citadel JSON only), allow: [domain], block: [domain],
//       skipped: {regex, options, other}}
// plainAs: what a bare "example.com" line means ("deny" or "allow"); AdGuard
// and hosts lines say it themselves. As in AdGuard, an allow for a domain
// wins over a block of the same domain.
var IMPORT_OPTIONS_OK = { important: true, all: true }
function importDomain(s) {
  var d = String(s || "").trim().toLowerCase().replace(/\.$/, "").replace(/^\*\./, "")
  if (isAddressLike(d)) return d
  return /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/.test(d) && d !== "localhost.localdomain" ? d : ""
}
function parseImport(text, plainAs) {
  var t = String(text || "").replace(/^\uFEFF/, "").trim()
  var out = { format: "", rules: null, allow: [], block: [], skipped: { regex: 0, options: 0, other: 0 } }
  if (t.charAt(0) === "{" || t.charAt(0) === "[") {
    try {
      var p = JSON.parse(t)
      var list = Array.isArray(p) ? p : (p && p.rules)
      if (Array.isArray(list)) { out.format = "citadel"; out.rules = list; return out }
    } catch (e) {}
  }
  var allow = {}, block = {}
  var seen = { adguard: 0, hosts: 0, plain: 0 }
  var lines = t.split(/\r?\n/)
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (!line || line.charAt(0) === "!" || line.charAt(0) === "#" || /^\[.*\]$/.test(line)) continue
    if (/##|#@#|#\$#|#\?#/.test(line)) { out.skipped.other++; continue }          // cosmetic filters
    line = line.replace(/\s+#.*$/, "")
    var isAllow = line.indexOf("@@") === 0
    if (isAllow) line = line.slice(2)
    if (line.charAt(0) === "/" && line.length > 2) { out.skipped.regex++; continue }
    var m = /^(0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+(.+)$/.exec(line)
    if (m) {                                                                     // hosts file
      seen.hosts++
      m[2].split(/\s+/).forEach(function(h) {
        var d = importDomain(h)
        if (d && d !== "localhost") block[d] = true
      })
      continue
    }
    m = /^\|\|([^\^\/$|]+)\^?\|?(?:\$(.*))?$/.exec(line)
    if (m) {                                                                     // AdGuard ||domain^$opts
      seen.adguard++
      var opts = m[2] ? m[2].split(",") : []
      if (opts.some(function(o) { return !IMPORT_OPTIONS_OK[o.trim().replace(/^~/, "")] })) { out.skipped.options++; continue }
      var ad = importDomain(m[1])
      if (!ad) { out.skipped.other++; continue }
      if (isAllow) allow[ad] = true; else block[ad] = true
      continue
    }
    var pd = importDomain(line)
    if (pd && !isAllow) {                                                        // bare domain (Pi-hole exact list)
      seen.plain++
      if (plainAs === "allow") allow[pd] = true; else block[pd] = true
      continue
    }
    if (pd && isAllow) { allow[pd] = true; seen.adguard++; continue }
    if (/[\\^$()|*+?\[\]{}]/.test(line)) out.skipped.regex++                    // Pi-hole regex lines
    else out.skipped.other++
  }
  out.allow = Object.keys(allow).sort()
  out.block = Object.keys(block).filter(function(d) { return !allow[d] }).sort()
  out.format = seen.adguard ? "adguard" : seen.hosts ? "hosts" : seen.plain ? "domains" : "unknown"
  return out
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
function ruleFromAlert(alert, action, scope, duration, profile, appInfo, viaScoped, route) {
  var conn = alert.conn
  var host = conn.host || conn.raddr
  return makeRule({
    profile: profile || "*",
    app: conn.exe || "*",
    via: viaScoped && conn.viaId ? conn.viaId : "*",
    route: action === "allow" && route ? route : "default",
    host: scope === "app" ? "*" : host,
    port: scope === "hostPort" ? conn.rport : "*",
    action: action,
    duration: duration === "untilQuit" ? "untilQuit" : "forever",
    pids: duration === "untilQuit" && appInfo ? appInfo.pids || [] : [],
    exeHash: appInfo && appInfo.trust ? appInfo.trust.hash || "" : "",
    origin: "gate"
  })
}

// Apps that install each version to its own path (mise, asdf, nvm, Nix, …):
// the path with its version parts replaced, or "" when it has none. Two paths
// of one family are the same app before and after an update.
var VERSION_PART = /^v?[0-9]+(\.[0-9]+)+([-+_~][0-9A-Za-z.+_~-]*)?$/
var NIX_STORE_PART = /^[0-9a-z]{32}-(.+?)(-[0-9][0-9A-Za-z.+_~-]*)?$/
function appFamily(exe) {
  if (!exe || String(exe).charAt(0) !== "/") return ""
  var parts = String(exe).split("/"), changed = false
  for (var i = 0; i < parts.length; i++) {
    if (VERSION_PART.test(parts[i])) {
      parts[i] = "*"
      changed = true
    } else if (i === 3 && parts[1] === "nix" && parts[2] === "store") {
      var m = NIX_STORE_PART.exec(parts[i])
      if (m) {
        parts[i] = "nix:" + m[1]
        changed = true
      }
    }
  }
  return changed ? parts.join("/") : ""
}

// The older path whose policies an updated app can keep: the newest policy's
// app of the same family, when this exact path has no policy yet. "" otherwise.
function updatedFrom(exe, rules) {
  var fam = appFamily(exe)
  if (!fam) return ""
  var best = null
  for (var i = 0; i < (rules || []).length; i++) {
    var r = rules[i]
    if (r.app === exe) return ""
    if (r.app && r.app !== "*" && appFamily(r.app) === fam && (!best || r.createdAt > best.createdAt)) best = r
  }
  return best ? best.app : ""
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
// Most specific first; deny before allow at equal specificity. Both the
// firewall spec and the proxy routes use this order.
function sortedActive(rules, ctx) {
  var active = (rules || []).filter(function(r) { return ruleActive(r, ctx) })
  active.sort(function(a, b) {
    var d = specificity(b) - specificity(a)
    if (d !== 0) return d
    return (a.action === "deny" ? 0 : 1) - (b.action === "deny" ? 0 : 1)
  })
  return active
}

// What one policy matches right now, as helper match entries
// [{cgroup?, targets?}]. Marks approx[rule.id] when the app shares its cgroup
// and can only be matched per destination.
function ruleTargets(r, ctx, conns, apps, uid, approx) {
  var out = []
  var hasApp = r.app && r.app !== "*"
  var hasHost = r.host && r.host !== "*"
  var port = r.port === "*" ? null : r.port
  if (!hasApp) {
    var t = hostTargets(r, conns, ctx.resolved, ctx.learned)
    if (t.length) out.push({ targets: t })
    return out
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
          .map(function(ip) { return { ip: ip, port: port } })
    if (vt.length) for (var v = 0; v < cgs.length; v++) out.push({ cgroup: cgs[v], targets: vt })
    return out
  }
  var info = apps ? apps[r.app] : null
  if (!info) return out                            // app not running
  var owned = (info.owned || []).filter(function(c) { return userCgroup(c, uid) })
  var all = (info.cgroups || []).filter(function(c) { return userCgroup(c, uid) })
  if (hasHost) {
    var tg = hostTargets(r, conns, ctx.resolved, ctx.learned)
    if (!tg.length) return out
    for (var a = 0; a < all.length; a++) out.push({ cgroup: all[a], targets: tg })
    if (all.length > owned.length) approx[r.id] = true
    return out
  }
  // whole app (optionally one port: any address on that port)
  var anyOnPort = port ? [{ ip: "0.0.0.0/0", port: port }, { ip: "::/0", port: port }] : null
  for (var o = 0; o < owned.length; o++)
    out.push(anyOnPort ? { cgroup: owned[o], targets: anyOnPort } : { cgroup: owned[o] })
  var shared = all.filter(function(c) { return owned.indexOf(c) === -1 })
  if (shared.length) {
    approx[r.id] = true
    // shared cgroup (e.g. a CLI inside a terminal): limit to what this app
    // is talking to, inside that cgroup only
    var dests = uniq(conns.filter(function(c) { return c.exe === r.app }).map(function(c) { return c.raddr })
      .concat(ctx.learned && ctx.learned[r.id] ? ctx.learned[r.id] : [])).sort()
    if (dests.length) {
      for (var s = 0; s < shared.length; s++)
        out.push({ cgroup: shared[s], targets: dests.map(function(ip) { return { ip: ip, port: port } }) })
    }
  }
  return out
}

function buildSpec(rules, ctx, conns, apps, blocklistCidrs, uid) {
  var entries = []
  var approx = {}
  var active = sortedActive(rules, ctx)
  var blocklistPlaced = false
  for (var i = 0; i < active.length; i++) {
    var r = active[i]
    var verdict = r.action === "deny" ? "drop" : "accept"
    // blocklists sit between host rules and app-only rules
    if (!blocklistPlaced && !(r.host && r.host !== "*") && r.app && r.app !== "*") {
      entries.push({ blocklist: true }); blocklistPlaced = true
    }
    ruleTargets(r, ctx, conns, apps, uid, approx).forEach(function(m) {
      entries.push(Object.assign({ verdict: verdict }, m))
    })
  }
  if (!blocklistPlaced) entries.push({ blocklist: true })
  return {
    spec: { silentDeny: ctx.mode === "lockdown", blocklist: blocklistCidrs || [], rules: entries },
    approx: approx
  }
}

// ------------------------------------------------------------------ proxy routes

// Listener port for a route: "default" follows the default route, "direct"
// is no port, a proxy id is that proxy's listener. A route naming a proxy
// that no longer exists gets DEAD_PORT, which nothing listens on, so the
// app fails closed instead of silently going direct.
var DEAD_PORT = 47000
function routePort(route, defaultRoute, proxiesById) {
  if (!route || route === "default") route = defaultRoute || "direct"
  if (route === "direct") return null
  var px = proxiesById[route]
  return px ? px.listen : DEAD_PORT
}

// Helper `proxy` section for the policies' routes and the default route, in
// the same most-specific-first order as the firewall spec. Deny policies are
// dropped by the filter chain before NAT, so they need no route. Returns
// null when nothing is routed through a proxy.
function compileRoutes(rules, defaultRoute, proxies, ctx, conns, apps, uid) {
  var byId = {}
  ;(proxies || []).forEach(function(p) { byId[p.id] = p })
  var out = []
  var any = false
  var approx = {}
  // Only policies that name a route (direct or a proxy) decide routing. A
  // plain Allow has no say, so "Edge via Office" still covers an Edge
  // destination that a narrower Allow let through; the rest takes the
  // default route (catch-all below).
  sortedActive(rules, ctx).forEach(function(r) {
    if (r.action === "deny" || !r.route || r.route === "default") return
    var port = routePort(r.route, defaultRoute, byId)
    if (port !== null) any = true
    ruleTargets(r, ctx, conns, apps, uid, approx).forEach(function(m) {
      out.push(Object.assign(port === null ? { verdict: "direct" } : { verdict: "redirect", port: port }, m))
    })
  })
  var defaultPort = routePort("default", defaultRoute, byId)
  if (!any && defaultPort === null) return null
  // never redirect the proxies' own traffic back into them
  var exclude = []
  ;(proxies || []).forEach(function(p) {
    var ips = isAddressLike(p.host) ? [p.host] : ((ctx.resolved || {})[normHost(p.host)] || [])
    ips.forEach(function(ip) { exclude.push(ip) })
  })
  return { rules: out, defaultPort: defaultPort, exclude: uniq(exclude).slice(0, 64) }
}

// Route label for a live connection: null (direct) or the proxy object.
function routeFor(conn, rules, ctx, defaultRoute, proxies) {
  if (!conn || conn.system) return null
  var r = bestRule(conn, rules, ctx)
  if (r && r.action === "deny") return null
  // the most specific matching policy that names a route (see compileRoutes)
  var routed = bestRule(conn, (rules || []).filter(function(x) {
    return x.action === "allow" && x.route && x.route !== "default"
  }), ctx)
  var route = routed ? routed.route : (defaultRoute || "direct")
  if (route === "direct") return null
  var px = (proxies || []).filter(function(p) { return p.id === route })[0]
  return px || { id: route, name: "missing proxy", missing: true }
}

// Lowest listener port >= 47001 not used by another proxy.
function freeListenPort(proxies) {
  var used = {}
  ;(proxies || []).forEach(function(p) { used[p.listen] = true })
  for (var port = 47001; port < 47100; port++) if (!used[port]) return port
  return 0
}

// Live sockets to tear down after a deny: [{cgroup, ip}]
// Live connections whose route just changed: a new or changed entry in the
// helper's proxy section (e.g. an app newly sent via a proxy, or restarted
// into a new scope). Cutting them makes the app reconnect along the new
// route; connections that already existed would otherwise keep going the way
// they started. Proxy servers themselves (exclude) are never cut.
function routeCutTargets(prev, next, conns, uid) {
  function key(e) { return JSON.stringify([e.verdict, e.port || 0, e.cgroup || "", e.targets || []]) }
  var before = {}
  ;((prev && prev.rules) || []).forEach(function(e) { before[key(e)] = true })
  var changed = ((next && next.rules) || []).filter(function(e) { return !before[key(e)] })
  var after = {}
  ;((next && next.rules) || []).forEach(function(e) { after[key(e)] = true })
  // entries that went away also move their traffic (e.g. back to direct)
  changed = changed.concat(((prev && prev.rules) || []).filter(function(e) { return !after[key(e)] }))
  if (!changed.length) return []
  var exclude = ((next && next.exclude) || []).concat((prev && prev.exclude) || [])
  return killTargets(conns, function(c) {
    if (c.proto !== "tcp" || c.scope === "loopback") return false
    if (exclude.some(function(x) { return netContains(x, c.raddr) })) return false
    return changed.some(function(e) {
      if (e.cgroup && e.cgroup !== c.cgroup) return false
      if (!e.targets || !e.targets.length) return true
      return e.targets.some(function(t) {
        return netContains(t.ip, c.raddr) && (t.port === null || t.port === undefined || Number(t.port) === Number(c.rport))
      })
    })
  }, uid)
}
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
