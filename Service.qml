import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons

import "Model.js" as Model

// Citadel's core, a child of the bar widget so it lives while the panel is
// closed. Streams bin/citadel-monitor, decides every connection against
// the rules, queues alerts, persists state.json and drives the root helper.
Item {
  id: root

  property var settings: ({})
  property string pluginDir: ""

  signal openRequested(string view)

  // ------------------------------------------------- paths
  readonly property string home: Quickshell.env("HOME") || ""
  readonly property string stateDir: home + "/.local/share/citadel"
  readonly property string statePath: stateDir + "/state.json"
  readonly property string specPath: stateDir + "/enforce/spec.json"
  readonly property string killPath: stateDir + "/enforce/kill.json"
  readonly property string monitorBin: pluginDir + "/bin/citadel-monitor"
  readonly property string explainBin: pluginDir + "/bin/citadel-explain"
  readonly property string helperBin: "/usr/lib/citadel/citadel-enforcer"
  property int uid: -1                      // reported by the monitor

  // ------------------------------------------------- persisted state
  property var rules: []
  property var profiles: [{ name: "Default", networks: [] }]
  property string profileOverride: ""
  property string mode: "guarded"           // guarded | open | lockdown
  property real silentUntil: 0              // epoch s, 0 = no timer
  property bool enforce: false
  property var lists: []
  property var decisionLog: []
  property var prefs: ({ interval: 2, alertTimeout: 90, alertDefault: "allow",
                         retentionDays: 30, notify: true, modeMinutes: 0, catchShort: true,
                         explainCommand: "", explainModel: "" })
  property bool loaded: false

  readonly property var defaultLists: [
    { id: "firehol1", name: "FireHOL Level 1 (attacks, malware)", kind: "ip",
      url: "https://iplists.firehol.org/files/firehol_level1.netset", enabled: false },
    { id: "spamhaus-drop", name: "Spamhaus DROP (hijacked networks)", kind: "ip",
      url: "https://www.spamhaus.org/drop/drop.txt", enabled: false },
    { id: "stevenblack", name: "StevenBlack hosts (ads, malware)", kind: "domain",
      url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", enabled: false },
    { id: "hagezi-light", name: "HaGeZi Light (trackers)", kind: "domain",
      url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt", enabled: false }
  ]

  // ------------------------------------------------- live state
  property var conns: []
  property var apps: ({})
  property var network: ({ names: [], ssid: "" })
  property var decisions: ({})              // conn.key -> Model.decide() result
  property var groups: []
  property var alerts: []                   // queue, oldest first
  property var session: ({})                // alertKey -> "allow"|"deny" (once)
  property var newApps: ({})                // updated apps you chose to treat as new (this session)
  property var resolved: ({})
  property var stats: ({ series: [], topAppsToday: [], topHostsToday: [], countriesToday: [], topApps7d: [] })
  property var listStatus: ({})
  property var ipCidrs: []
  property var geoip: ({ installed: false, error: "" })
  property var approx: ({})
  property var protectedPids: ({})          // Citadel's monitor and the shell hosting it
  property var recentShort: []              // short connections the poll missed (newest first)
  property var kernelLog: ({ running: false, error: "", seen: 0 })
  property var dnsNames: ({ state: "off", error: "", seen: 0 })
  property string helperVersion: ""         // from `citadel-enforcer status` (1.2+)
  property bool helperLogging: false
  readonly property bool helperSupportsShort: helperVersion !== "" && Number(helperVersion.split(".")[1]) >= 2
  property var learned: ({})                // ruleId -> {ip: lastSeen}, see Model.learnTargets
  property var rate: ({ up: 0, down: 0 })
  property var totals: ({ connections: 0, apps: 0, denied: 0 })
  property string monitorError: ""
  property bool monitorUp: false
  property int ticks: 0
  property real now: Date.now() / 1000

  readonly property string activeProfile: Model.activeProfile(profiles, profileOverride, network.names || [])
  readonly property bool silent: mode !== "guarded"

  // environment checks (shown in Settings)
  readonly property string testedOmarchy: "4"    // major version Citadel is built against
  property string omarchyVersion: ""
  readonly property bool omarchySupported: omarchyVersion === "" || omarchyVersion.split(".")[0] === testedOmarchy
  property bool inWheel: true

  // enforcement
  property bool helperInstalled: false
  property bool enforceActive: false
  property bool enforceBusy: false
  property string enforceError: ""
  property real enforceAppliedAt: 0
  property int enforceDrops: 0
  // citadel-helper 1.1.1 fixed kill requests that could close other users'
  // sockets; older helpers report no version at all
  readonly property string minHelper: "1.1.1"
  readonly property string minProxyHelper: "1.3.0"      // proxy routing (nat redirect)
  readonly property bool proxyCapable: helperUsable && !Model.versionLess(helperVersion, minProxyHelper)

  // ------------------------------------------------- proxies (persisted)
  // [{id, name, type: http|https|socks5, host, port, listen, auth, verifyTls}]
  property var proxies: []
  property string defaultRoute: "direct"      // "direct" or a proxy id
  // live, from citadel-proxy: id -> {ok, ms, error, ts}; recent failures
  property var proxyStatus: ({})
  property var proxyLog: []
  property var proxyCarried: []              // [{ts, counts: {id: n}}], last 5 min of stats events
  property var _proxyFailed: ({})             // "ip|port" -> ts of the last proxy failure
  property var proxyCheck: ({})               // id -> result of the last Check
  property string proxyError: ""              // e.g. helper too old for routing
  readonly property var helperGate: Model.helperGate(helperInstalled, helperVersion, minHelper)
  // the only condition under which apply / kill may be sent to the helper
  readonly property bool helperUsable: helperGate.usable
  readonly property bool helperOutdated: helperGate.reason === "outdated"
  // "is older than 1.1.1" / "is an unreleased build" + " and has a security bug"
  readonly property string helperProblem: !helperOutdated ? ""
    : (Model.versionLess(helperVersion, minHelper) ? "is older than " + minHelper : "is an unreleased build")
      + " and has a security bug"
  property string _lastSpec: ""
  property var _appliedRoutes: null         // proxy section of the last applied spec
  property var _pendingRoutes: null         // ... of the spec being applied

  // ------------------------------------------------- persistence
  FileView {
    id: stateFile
    path: root.statePath
    watchChanges: false
    atomicWrites: true
    printErrors: false
    onLoaded: root._load(text())
    onLoadFailed: root._load("")
  }

  function _load(raw) {
    var s = {}
    try { s = raw && String(raw).length ? JSON.parse(String(raw)) : {} } catch (e) { s = {} }
    if (s.version === 2) {
      rules = (s.rules || []).map(function(r) { return Model.makeRule(r) })
      profiles = (s.profiles && s.profiles.length) ? s.profiles : [{ name: "Default", networks: [] }]
      profileOverride = s.profileOverride || ""
      // older builds used prompt / silentAllow / silentDeny
      var legacy = { prompt: "guarded", silentAllow: "open", silentDeny: "lockdown" }
      var m = legacy[s.mode] || s.mode
      mode = ["guarded", "open", "lockdown"].indexOf(m) !== -1 ? m : "guarded"
      silentUntil = Number(s.silentUntil) || 0
      enforce = !!s.enforce
      decisionLog = s.decisionLog || []
      var p = s.prefs || {}
      prefs = Object.assign({}, prefs, p)
      proxies = (s.proxies || []).filter(function(x) { return x && x.id && x.listen })
      defaultRoute = s.defaultRoute || "direct"
    }
    // merge built-in list catalogue with saved subscriptions
    var saved = {}
    ;(s.lists || []).forEach(function(l) { saved[l.id] = l })
    var merged = defaultLists.map(function(d) { return Object.assign({}, d, saved[d.id] || {}) })
    ;(s.lists || []).forEach(function(l) { if (!defaultLists.some(function(d) { return d.id === l.id })) merged.push(l) })
    lists = merged
    loaded = true
    save()
    _sendConfig()
    _configureProxy()
    if (enforce) _syncEnforcement(true)
  }

  function save() {
    if (!loaded) return
    saveTimer.restart()
  }
  function _stateText() {
    return JSON.stringify({
      version: 2, rules: root.rules, profiles: root.profiles, profileOverride: root.profileOverride,
      mode: root.mode, silentUntil: root.silentUntil, enforce: root.enforce, lists: root.lists,
      decisionLog: root.decisionLog.slice(0, 300), prefs: root.prefs,
      proxies: root.proxies, defaultRoute: root.defaultRoute
    }, null, 2) + "\n"
  }
  Timer {
    id: saveTimer
    interval: 300
    onTriggered: stateFile.setText(root._stateText())
  }
  // a shell restart or plugin reload must not drop a pending save
  Component.onDestruction: if (saveTimer.running) stateFile.setText(root._stateText())

  // ------------------------------------------------- monitor stream
  Process {
    id: monitor
    command: [root.monitorBin]
    stdinEnabled: true
    stdout: SplitParser { onRead: function(line) { root._onMonitorLine(line) } }
    stderr: StdioCollector { id: monitorErr; waitForEnd: true }
    onStarted: { root.monitorUp = true; root.monitorError = ""; root._sendConfig() }
    onExited: function(code) {
      root.monitorUp = false
      root.monitorError = "monitor stopped (exit " + code + ") " + String(monitorErr.text || "").slice(-300)
      restartMonitor.restart()
    }
  }
  Timer { id: restartMonitor; interval: 3000; onTriggered: monitor.running = true }

  function _send(obj) {
    if (monitor.running) monitor.write(JSON.stringify(obj) + "\n")
  }

  function _sendConfig() {
    if (!loaded) return
    var hosts = {}
    rules.forEach(function(r) { if (r.host !== "*" && !Model.isAddressLike(r.host)) hosts[r.host] = true })
    proxies.forEach(function(x) { if (!Model.isAddressLike(x.host)) hosts[Model.normHost(x.host)] = true })
    _send({ cmd: "config", interval: Number(prefs.interval) || 2, retentionDays: Number(prefs.retentionDays) || 30,
            resolveHosts: Object.keys(hosts), lists: lists })
  }

  function _onMonitorLine(line) {
    var m
    try { m = JSON.parse(line) } catch (e) { return }
    if (m.type === "tick") _onTick(m)
    else if (m.type === "stats") stats = m
    else if (m.type === "resolved") { resolved = m.hosts || {}; _reevaluate() }
    else if (m.type === "lists") {
      var st = {}
      ;(m.lists || []).forEach(function(l) { st[l.id] = l })
      listStatus = st
      ipCidrs = m.ipCidrs || []
      _reevaluate()
    }
    else if (m.type === "geoip") geoip = m
    else if (m.type === "log") console.warn("[citadel] monitor:", m.msg)
  }

  function _ctx() {
    var alive = {}
    for (var exe in apps) (apps[exe].pids || []).forEach(function(p) { alive[p] = true })
    return { profile: activeProfile, mode: mode, resolved: resolved, alivePids: alive, session: session,
             learned: Model.learnedIps(learned), learnedCg: Model.learnedCgroups(learned) }
  }

  function _onTick(m) {
    now = m.ts || Date.now() / 1000
    if (m.uid !== undefined) uid = m.uid
    if (m.selfPid) { var pp = {}; pp[m.selfPid] = true; pp[m.shellPid] = true; protectedPids = pp }
    conns = m.conns || []
    apps = m.apps || {}
    network = m.network || { names: [], ssid: "" }
    if (m.kernelLog) kernelLog = m.kernelLog
    if (m.dnsNames) dnsNames = m.dnsNames
    var first = ticks === 0
    ticks++
    _pruneExpiredRules()
    learned = Model.learnTargets(learned, rules, conns, now, 3600)
    var ctx = _ctx()
    var dec = {}
    var up = 0, down = 0, denied = 0
    var newAlerts = alerts.slice()
    var logged = []
    for (var i = 0; i < conns.length; i++) {
      var c = conns[i]
      var d = _decide(c, ctx)
      dec[c.key] = d
      up += c.upRate || 0
      down += c.downRate || 0
      if (d.verdict === "deny") denied++
      if (!first && c.new) {
        if (d.verdict === "prompt") _queueAlert(newAlerts, c, d)
        else if (d.source === "silent" || d.source === "blocklist")
          logged.push(_logEntry(c, d.verdict, d.source === "blocklist" ? "feed " + (c.list || "") : (mode === "open" ? "open mode" : "lockdown")))
      }
    }
    decisions = dec
    groups = Model.groupByApp(conns, dec)
    rate = { up: up, down: down }
    totals = { connections: conns.length, apps: groups.length, denied: denied }
    // connections that ended before the poll saw them (kernel log, helper 1.2+)
    var shorts = m.short || []
    if (shorts.length) {
      var recent = []
      for (var k = 0; k < shorts.length; k++) {
        var sc = shorts[k]
        var sd = _decide(sc, ctx)
        recent.push({ conn: sc, decision: sd })
        if (first) continue
        // a routed connection the proxy just reset: already blocked and logged,
        // and too short for the app to be named reliably
        if (_proxyFailed[sc.raddr + "|" + sc.rport] > now - 10) continue
        var trusted = sc.confidence === "matched" || sc.confidence === "likely"
        if (sd.verdict === "prompt" && trusted) _queueAlert(newAlerts, sc, sd)
        else if (sd.source === "silent" || sd.source === "blocklist")
          logged.push(_logEntry(sc, sd.verdict, sd.source === "blocklist" ? "feed " + (sc.list || "") : (mode === "open" ? "open mode" : "lockdown")))
      }
      // merge repeats of the same app + launcher + destination within a minute
      var merged = recentShort.slice()
      recent.reverse().forEach(function(item) {
        var c = item.conn
        for (var r = 0; r < merged.length; r++) {
          var o = merged[r].conn
          if (o.exe === c.exe && (o.viaId || "") === (c.viaId || "") && o.raddr === c.raddr
              && o.rport === c.rport && c.ts - o.ts < 60) {
            merged[r] = { conn: c, decision: item.decision, count: (merged[r].count || 1) + 1 }
            merged.unshift(merged.splice(r, 1)[0])
            return
          }
        }
        merged.unshift({ conn: c, decision: item.decision, count: 1 })
      })
      recentShort = merged.slice(0, 60)
    }
    if (newAlerts.length !== alerts.length) alerts = newAlerts
    if (logged.length) _log(logged)
    // first tick after a start or plugin reload: the uid is known now, so
    // re-apply for sure (the load-time sync may have run before it was)
    if (enforce) _syncEnforcement(first)
  }

  // Model.decide, plus two gate cases: an allowed program that changed since
  // (same path, new checksum), and an app that updated to a new path (mise,
  // asdf, nvm, Nix …) while its policies are still on the old one.
  function _decide(c, ctx) {
    var d = Model.decide(c, rules, ctx)
    if (d.source === "rule" && d.verdict === "allow" && d.rule.exeHash && c.exe && apps[c.exe]) {
      var h = (apps[c.exe].trust || {}).hash
      if (h && h !== d.rule.exeHash) d = { verdict: "prompt", source: "changed", rule: d.rule }
    } else if (d.verdict === "prompt" && d.source === "none" && c.exe && !newApps[c.exe]) {
      var old = Model.updatedFrom(c.exe, rules)
      if (old) d = { verdict: "prompt", source: "updated", rule: null, from: old }
    }
    return d
  }

  // ------------------------------------------------- alerts
  // one request per destination; an updated app asks once for all of them
  function _queueAlert(queue, conn, d) {
    var key = d.source === "updated" ? "update|" + conn.exe : Model.alertKey(conn)
    for (var i = 0; i < queue.length; i++) if (queue[i].key === key) return
    var info = apps[conn.exe] || null
    var alert = { key: key, conn: conn, firstSeen: now, changed: d.source === "changed", short: !!conn.short,
                  trust: info ? info.trust : { level: "unknown" }, hasOwnScope: !!(info && info.owned && info.owned.length) }
    if (d.source === "updated") {
      alert.updatedFrom = d.from
      alert.policies = rules.filter(function(r) { return r.app === d.from }).length
    }
    queue.push(alert)
    if (prefs.notify !== false) _noteLater(alert)
  }

  // An updated app: "keep" moves the old path's policies to the new one;
  // anything else asks about it like a new app (connection by connection).
  function _answerUpdate(alert, choice, source) {
    var exe = alert.conn.exe, old = alert.updatedFrom
    alerts = alerts.filter(function(a) { return a.key !== alert.key })
    if (choice === "keep") {
      var h = ((apps[exe] || {}).trust || {}).hash || ""
      rules = rules.map(function(r) {
        return r.app === old ? Model.makeRule(Object.assign({}, r, { app: exe, exeHash: r.exeHash ? h : "" })) : r
      })
      _log([_logEntry(alert.conn, "allow", source || "you · kept its policies after an update")])
      save()
      _sendConfig()
      _reevaluate()
      if (enforce) _syncEnforcement(true)
      return
    }
    var n = Object.assign({}, newApps)
    n[exe] = true
    newApps = n
    var ctx = _ctx(), queue = alerts.slice()
    conns.forEach(function(c) {
      if (c.exe !== exe) return
      var d = _decide(c, ctx)
      if (d.verdict === "prompt") _queueAlert(queue, c, d)
    })
    alerts = queue
    _reevaluate()
  }

  // Answer the oldest (or given) alert.
  // action: allow|deny ; scope: hostPort|host|app ; duration: once|untilQuit|forever
  // viaScoped: the policy only covers the app when started by the same launcher
  function answer(key, action, scope, duration, source, viaScoped, route) {
    var alert = null
    for (var i = 0; i < alerts.length; i++) if (alerts[i].key === key) { alert = alerts[i]; break }
    if (!alert) return
    if (alert.updatedFrom) return _answerUpdate(alert, action, source)
    if (duration === "once") {
      var s = Object.assign({}, session)
      s[key] = action
      session = s
    } else {
      var info = apps[alert.conn.exe] || null
      // replace a stale rule for a changed binary
      if (alert.changed) rules = rules.filter(function(r) { return !(r.app === alert.conn.exe && r.exeHash) })
      addRule(Model.ruleFromAlert(alert, action, scope, duration, "*", info, viaScoped === true, route), true)
    }
    if (action === "deny") {
      var exe = alert.conn.exe, dest = alert.conn.raddr, port = alert.conn.rport, viaId = alert.conn.viaId || ""
      _kill(Model.killTargets(conns, function(c) {
        if (c.exe !== exe) return false
        if (viaScoped === true && (c.viaId || "") !== viaId) return false
        if (scope === "app") return true
        if (scope === "hostPort" && c.rport !== port) return false
        return c.raddr === dest || (alert.conn.host && c.host === alert.conn.host)
      }, uid))
    }
    _log([_logEntry(alert.conn, action, source || (duration === "once" ? "you · once" : duration === "untilQuit" ? "you · until quit" : "you · from now on"))])
    alerts = alerts.filter(function(a) { return a.key !== key })
    _reevaluate()
  }

  Timer {
    // alert timeouts + silent-mode timer + clock
    interval: 1000
    running: true
    repeat: true
    onTriggered: {
      root.now = Date.now() / 1000
      if (root.silentUntil > 0 && root.now >= root.silentUntil) root.setMode("guarded", 0)
      var limit = Number(root.prefs.alertTimeout) || 0
      if (limit > 0) {
        var expired = root.alerts.filter(function(a) { return root.now - a.firstSeen > limit })
        expired.forEach(function(a) {
          root.answer(a.key, root.prefs.alertDefault === "deny" ? "deny" : "allow", "hostPort", "once", "timeout")
        })
      }
    }
  }

  // A burst of requests from one app (a new session opening ten connections)
  // shares one notification.
  property var _notePending: ({})           // app key -> true
  function _noteKey(alert) {
    return alert.updatedFrom ? alert.key : "app|" + (alert.conn.exe || alert.conn.app || "?") + "|" + (alert.conn.viaId || "")
  }
  function _noteLater(alert) {
    var p = Object.assign({}, _notePending)
    p[_noteKey(alert)] = true
    _notePending = p
    noteTimer.restart()
  }
  Timer {
    id: noteTimer
    interval: 400
    onTriggered: {
      var keys = Object.keys(root._notePending)
      root._notePending = {}
      keys.forEach(function(k) {
        var waiting = root.alerts.filter(function(a) { return root._noteKey(a) === k })
        if (waiting.length) root._notify(waiting)
      })
    }
  }

  Process { id: notifyProc; stdout: StdioCollector { id: notifyOut; waitForEnd: true }
    onExited: if (String(notifyOut.text || "").indexOf("default") !== -1) root.openRequested("gate") }
  function _notify(waiting) {
    var a = waiting[0], conn = a.conn
    var title, body
    if (a.updatedFrom) {
      title = "Updated app at the gate"
      body = Model.appWithOrigin(conn) + " updated · " + a.policies + (a.policies === 1 ? " policy" : " policies")
           + " for the old version: keep them?"
    } else {
      title = waiting.some(function(x) { return x.changed }) ? "Changed app at the gate" : "At the gate"
      var dests = waiting.map(function(x) { return Model.destLabel(x.conn) + ":" + x.conn.rport })
      body = Model.appWithOrigin(conn) + " → " + dests.slice(0, 2).join(", ")
           + (dests.length > 2 ? " and " + (dests.length - 2) + " more" : "")
    }
    var cmd = ["notify-send", "-a", "Citadel", title, body]
    if (notifyProc.running) { Quickshell.execDetached(cmd); return }
    notifyProc.command = cmd.slice(0, 1).concat(["-A", "default=Decide", "-w"], cmd.slice(1))
    notifyProc.running = true
  }

  // ------------------------------------------------- decision log
  function _logEntry(conn, verdict, source) {
    return { ts: now, app: Model.appWithOrigin(conn), exe: conn.exe || "", via: conn.viaId || "", dest: Model.destLabel(conn),
             ip: conn.raddr, port: conn.rport, cc: conn.cc || "", verdict: verdict, source: source }
  }
  function _log(entries) {
    decisionLog = entries.concat(decisionLog).slice(0, 300)
    save()
  }
  function clearLog() { decisionLog = []; save() }

  // ------------------------------------------------- rules
  function addRule(rule, fromAlert) {
    var r = Model.makeRule(rule)
    // same match fields -> replace
    rules = rules.filter(function(x) {
      return !(x.profile === r.profile && x.app === r.app && (x.via || "*") === r.via && x.host === r.host && x.port === r.port)
    }).concat([r])
    if (!fromAlert && r.action === "deny") {
      var ctx = _ctx()
      _kill(Model.killTargets(conns, function(c) { return Model.ruleMatches(r, c, ctx) }, uid))
    }
    save()
    _sendConfig()
    _reevaluate()
    if (enforce) _syncEnforcement(true)
    return r
  }
  function updateRule(id, fields) {
    rules = rules.map(function(r) { return r.id === id ? Model.makeRule(Object.assign({}, r, fields, { id: id })) : r })
    save(); _sendConfig(); _reevaluate()
    if (enforce) _syncEnforcement(true)
  }
  function removeRule(id) {
    rules = rules.filter(function(r) { return r.id !== id })
    save(); _sendConfig(); _reevaluate()
    if (enforce) _syncEnforcement(true)
  }
  function _pruneExpiredRules() {
    var ctx = _ctx()
    var keep = rules.filter(function(r) { return r.duration !== "untilQuit" || Model.ruleActive(r, Object.assign({}, ctx, { profile: r.profile })) })
    if (keep.length !== rules.length) { rules = keep; save() }
  }
  // quick actions from the monitor view
  function allowApp(exe, viaId) { addRule({ app: exe, via: viaId || "*", action: "allow" }) }
  function denyApp(exe, viaId) { addRule({ app: exe, via: viaId || "*", action: "deny" }) }
  function denyConn(conn) { addRule({ app: conn.exe || "*", via: conn.viaId || "*", host: conn.host || conn.raddr, action: "deny" }) }
  function allowConn(conn) { addRule({ app: conn.exe || "*", via: conn.viaId || "*", host: conn.host || conn.raddr, action: "allow" }) }

  // ------------------------------------------------- kill (your own processes only)
  // Session pieces that must never be killed from here.
  readonly property var protectedNames: ["quickshell", "qs", "Hyprland", "hyprland", "systemd", "uwsm",
    "dbus-broker", "dbus-broker-launch", "dbus-daemon", "pipewire", "pipewire-pulse", "wireplumber",
    "Xwayland", "xdg-desktop-portal", "xdg-desktop-portal-hyprland", "gnome-keyring-daemon"]

  function _isProtectedCmd(cmd) {
    var first = String(cmd || "").split(" ").slice(0, 3).join(" ")
    return protectedNames.some(function(n) { return new RegExp("(^|[/\\s])" + n + "(\\s|$)").test(first) })
  }

  // pids to kill for a Traffic group:
  //  - a normal app: every process of that program
  //  - "app via launcher", or an interpreter (python, node, bash…): only the
  //    processes owning this group's connections, never every script that
  //    happens to run on the same interpreter
  function killablePids(group) {
    if (!group || group.system || !group.exe) return []
    var name = group.exe.split("/").pop()
    if (protectedNames.indexOf(name) !== -1) return []
    var interpreter = /^(python|node|perl|ruby|bash|sh|dash|zsh|fish|lua|luajit|deno|bun|php)[0-9.]*$/.test(name)
    var pids = []
    if (group.viaId || interpreter)
      group.conns.forEach(function(c) { if (c.pid && !_isProtectedCmd(c.cmd)) pids.push(c.pid) })
    else pids = ((apps[group.exe] || {}).pids || []).slice()
    var seen = {}
    return pids.filter(function(p) {
      if (!p || seen[p] || protectedPids[p]) return false
      seen[p] = true
      return true
    })
  }
  function killGroup(group, force) {
    var pids = killablePids(group)
    if (!pids.length) return 0
    Quickshell.execDetached(["kill", force ? "-KILL" : "-TERM"].concat(pids.map(String)))
    var c = group.conns && group.conns.length ? group.conns[0] : { app: group.app, exe: group.exe }
    _log([{ ts: now, app: Model.appWithOrigin(c), exe: group.exe, via: group.viaId || "", dest: pids.length + " process(es)",
            ip: "", port: "", cc: "", verdict: "deny", source: force ? "force-killed by you" : "killed by you" }])
    return pids.length
  }
  function stillRunning(pids) {
    var alive = {}
    for (var exe in apps) (apps[exe].pids || []).forEach(function(p) { alive[p] = true })
    return (pids || []).filter(function(p) { return alive[p] }).length
  }

  function exportRules() { return JSON.stringify({ version: 2, rules: rules }, null, 2) }
  // Several policies at once: one save, one config, one firewall update.
  function addRules(list) {
    var added = list.map(function(f) { return Model.makeRule(f) })
    var key = function(r) { return [r.profile, r.app, r.via || "*", r.host, r.port].join("|") }
    var fresh = {}
    added.forEach(function(r) { fresh[key(r)] = true })
    rules = rules.filter(function(x) { return !fresh[key(x)] }).concat(added)
    save(); _sendConfig(); _reevaluate()
    if (enforce) _syncEnforcement(true)
    return added.length
  }

  // A big domain list becomes a feed: a subscription when it came from a URL
  // (kept up to date like the built-in feeds), else a local list file.
  readonly property int importFeedThreshold: 200
  FileView { id: importFile; atomicWrites: true; printErrors: false; watchChanges: false
    property var entry: null
    onSaved: { root.lists = root.lists.concat([entry]); entry = null; root.save(); root._sendConfig() }
    onSaveFailed: entry = null }
  function importFeed(name, domains, url) {
    if (url) { addList(name, url, "domain"); return }
    var id = "import-" + Date.now().toString(36)
    importFile.entry = { id: id, name: name, url: "", local: true, kind: "domain", enabled: true }
    importFile.path = stateDir + "/lists/" + id + ".txt"
    importFile.setText(domains.join("\n") + "\n")
  }

  // Import from pasted text or a fetched file. opts: {plainAs: "deny"|"allow", url, name}
  // Returns a one-line summary for the Policies view.
  function importText(text, opts) {
    var o = opts || {}
    var p = Model.parseImport(text, o.plainAs)
    if (p.format === "citadel") {
      var err = importRules(JSON.stringify(p.rules))
      return err ? "Import failed: " + err : "Imported " + p.rules.length + " Citadel policies."
    }
    if (!p.allow.length && !p.block.length) return "Nothing to import: no domains found."
    var note = "imported" + (o.name ? " from " + o.name : "")
    var list = p.allow.map(function(d) { return { host: d, action: "allow", note: note } })
    var asFeed = p.block.length > importFeedThreshold
    if (!asFeed) list = list.concat(p.block.map(function(d) { return { host: d, action: "deny", note: note } }))
    if (list.length) addRules(list)
    if (asFeed) importFeed((o.name || "Imported list") + " (" + p.block.length + ")", p.block, o.url || "")
    var parts = []
    if (p.block.length) parts.push(asFeed ? p.block.length + " blocked domains as a feed" : p.block.length + " block policies")
    if (p.allow.length) parts.push(p.allow.length + " allow policies")
    var sk = []
    if (p.skipped.regex) sk.push(p.skipped.regex + " regex")
    if (p.skipped.options) sk.push(p.skipped.options + " with options Citadel can't apply")
    if (p.skipped.other) sk.push(p.skipped.other + " other")
    return "Imported " + parts.join(" and ") + " (" + p.format + ")." + (sk.length ? " Skipped " + sk.join(", ") + "." : "")
  }

  function importRules(text) {
    var p
    try { p = JSON.parse(text) } catch (e) { return "not valid JSON" }
    var list = Array.isArray(p) ? p : (p.rules || [])
    if (!Array.isArray(list)) return "no rules found"
    list.forEach(function(r) { addRule(r) })
    return ""
  }

  // re-decide current connections after a rule/list/mode change
  function _reevaluate() {
    var ctx = _ctx()
    var dec = {}
    var denied = 0
    for (var i = 0; i < conns.length; i++) {
      var d = Model.decide(conns[i], rules, ctx)
      dec[conns[i].key] = d
      if (d.verdict === "deny") denied++
    }
    decisions = dec
    groups = Model.groupByApp(conns, dec)
    totals = { connections: conns.length, apps: groups.length, denied: denied }
    // drop queued alerts that are now answered by a rule, a list or the mode
    var still = alerts.filter(function(a) { return Model.decide(a.conn, rules, ctx).verdict === "prompt" || a.changed })
    if (still.length !== alerts.length) alerts = still
    if (enforce) _syncEnforcement(false)
  }

  // ------------------------------------------------- modes and profiles
  function setMode(m, minutes) {
    mode = ["guarded", "open", "lockdown"].indexOf(m) !== -1 ? m : "guarded"
    silentUntil = mode !== "guarded" && minutes > 0 ? Date.now() / 1000 + minutes * 60 : 0
    save(); _reevaluate()
    if (enforce) _syncEnforcement(true)
  }
  function setProfileOverride(name) {
    profileOverride = name || ""
    save(); _reevaluate()
    if (enforce) _syncEnforcement(true)
  }
  function addProfile(name) {
    name = String(name || "").trim()
    if (!name || profiles.some(function(p) { return p.name === name })) return
    profiles = profiles.concat([{ name: name, networks: [] }])
    save()
  }
  function removeProfile(name) {
    if (profiles.length <= 1) return
    profiles = profiles.filter(function(p) { return p.name !== name })
    rules = rules.filter(function(r) { return r.profile !== name })
    if (profileOverride === name) profileOverride = ""
    save(); _reevaluate()
  }
  function toggleProfileNetwork(name, net) {
    profiles = profiles.map(function(p) {
      if (p.name !== name) {
        // a network belongs to one profile only
        return { name: p.name, networks: (p.networks || []).filter(function(n) { return n !== net }) }
      }
      var nets = (p.networks || []).slice()
      var i = nets.indexOf(net)
      if (i === -1) nets.push(net); else nets.splice(i, 1)
      return { name: p.name, networks: nets }
    })
    save(); _reevaluate()
  }
  function setPref(key, value) {
    var p = Object.assign({}, prefs)
    p[key] = value
    prefs = p
    save()
    if (key === "interval" || key === "retentionDays") _sendConfig()
    if (key === "catchShort" && enforce) _syncEnforcement(true)
  }

  // ------------------------------------------------- blocklists + geoip
  function setListEnabled(id, on) {
    lists = lists.map(function(l) { return l.id === id ? Object.assign({}, l, { enabled: !!on }) : l })
    save(); _sendConfig()
  }
  function addList(name, url, kind) {
    url = String(url || "").trim()
    if (!/^https?:\/\//.test(url)) return
    var id = "custom-" + Date.now().toString(36)
    lists = lists.concat([{ id: id, name: name || url, url: url, kind: kind === "ip" ? "ip" : "domain", enabled: true }])
    save(); _sendConfig()
  }
  function removeList(id) {
    lists = lists.filter(function(l) { return l.id !== id || defaultLists.some(function(d) { return d.id === id }) })
    save(); _sendConfig()
  }
  function refreshLists() { _send({ cmd: "refreshLists" }) }
  function downloadGeoip() { geoip = Object.assign({}, geoip, { downloading: true }); _send({ cmd: "geoipDownload" }) }
  function requestStats() { _send({ cmd: "stats" }) }

  // ------------------------------------------------- enforcement (root helper)
  Process {
    id: helperCheck
    command: ["test", "-x", root.helperBin]
    onExited: function(code) {
      var was = root.helperInstalled
      root.helperInstalled = code === 0
      if (!root.helperInstalled) root.helperVersion = ""
      if (!was && root.helperInstalled) root.verifyHelper()
    }
  }
  // pick the helper up as soon as the package is installed
  Timer { interval: 10000; repeat: true; running: !root.helperInstalled; onTriggered: helperCheck.running = true }
  // any upgrade (not only from an outdated helper) changes the file: re-check
  // the version then. `stat` needs no privileges, unlike `status`.
  property string _helperStamp: ""
  Process {
    id: helperStat
    command: ["stat", "-c", "%Y %s", root.helperBin]
    stdout: StdioCollector { id: helperStatOut; waitForEnd: true }
    onExited: function(code) {
      var st = code === 0 ? helperStatOut.text.trim() : ""
      if (root._helperStamp !== "" && st !== "" && st !== root._helperStamp) root.verifyHelper()
      root._helperStamp = st
    }
  }
  Timer { interval: 15000; repeat: true; running: root.helperInstalled; triggeredOnStart: true; onTriggered: helperStat.running = true }
  // an outdated helper may be upgraded at any time: re-check its version
  Timer { interval: 60000; repeat: true; running: root.helperInstalled && root.helperOutdated; onTriggered: root.verifyHelper() }

  // Ask the helper for its version (read-only `status`) before anything else.
  // Helpers before 1.1.1 report no version; they are treated as 1.1.0.
  function verifyHelper() {
    if (!helperInstalled) return
    _run(["status"], function(code, out) {
      var s = {}
      try { s = JSON.parse(out) } catch (e) {}
      root.helperVersion = code === 0 ? (s.version || "1.1.0") : ""
      if (code === 0) {
        root.enforceActive = !!s.active
        root.enforceDrops = Number(s.drops) || 0
      }
      if (root.helperOutdated) {
        root.enforceError = root.enforce
          ? "Enforcement paused: citadel-helper " + root.helperVersion + " " + root.helperProblem + ". Update it (see below)."
          : ""
      } else if (root.helperUsable) {
        if (root.enforceError.indexOf("citadel-helper") !== -1) root.enforceError = ""
        if (root.enforce) { root._lastSpec = ""; root._syncEnforcement(true) }
      }
    })
  }

  property var _jobs: []
  Process {
    id: helperProc
    property var job: null
    stdout: StdioCollector { id: helperOut; waitForEnd: true }
    stderr: StdioCollector { id: helperErr; waitForEnd: true }
    onExited: function(code) {
      var j = helperProc.job
      helperProc.job = null
      var out = String(helperOut.text || ""), err = String(helperErr.text || "")
      if (j && j.done) j.done(code, out, err)
      root._pump()
    }
  }
  function _run(args, done) {
    // Single choke point for privileged calls: "apply" and "kill" are only
    // ever sent to a helper whose verified version is >= minHelper.
    // ("status" and "off" are safe with any helper.)
    if ((args[0] === "apply" || args[0] === "kill") && !helperUsable) {
      if (done) done(1, "", "refused: citadel-helper " + (helperVersion || "version unknown") + " is not >= " + minHelper)
      return
    }
    _jobs = _jobs.concat([{ args: args, done: done }])
    _pump()
  }
  function _pump() {
    if (helperProc.running || !_jobs.length) return
    var j = _jobs[0]
    _jobs = _jobs.slice(1)
    helperProc.job = j
    helperProc.command = ["pkexec", helperBin].concat(j.args)
    helperProc.running = true
  }

  FileView {
    id: specFile
    path: root.specPath
    atomicWrites: true
    printErrors: false
    watchChanges: false
    onSaved: root._run(["apply", root.specPath], function(code, out, err) {
      root.enforceBusy = false
      if (code === 0) {
        root.enforceActive = true
        root.enforceError = ""
        root.enforceAppliedAt = Date.now() / 1000
        // connections opened before a route changed keep their old path:
        // cut them so the apps reconnect through (or around) the proxy
        var cut = Model.routeCutTargets(root._appliedRoutes, root._pendingRoutes, root.conns, root.uid)
        root._appliedRoutes = root._pendingRoutes
        if (cut.length) root._kill(cut)
        // (apply only runs once the helper version was verified)
      } else {
        root.enforceActive = false
        root._lastSpec = ""
        root.enforceError = code === 126 || code === 127 ? root._authHelp()
          : (err || out || ("helper exit " + code)).trim().slice(0, 400)
        if (code === 126 || code === 127) { root.enforce = false; root.save() }
      }
    })
    onSaveFailed: { root.enforceBusy = false; root.enforceError = "could not write " + root.specPath }
  }
  FileView {
    id: killFile
    path: root.killPath
    atomicWrites: true
    printErrors: false
    watchChanges: false
    onSaved: root._run(["kill", root.killPath], null)
  }

  // Rule changes (force) apply after a short debounce; background changes
  // (new IPs learned from traffic) at most every 5 s.
  Timer { id: syncTimer; interval: 400; onTriggered: root._doSync() }
  property bool _forceSync: false
  property real _lastSyncAt: 0
  function _syncEnforcement(force) {
    if (force) _forceSync = true
    var wait = _forceSync ? 400 : Math.max(400, 5000 - (Date.now() - _lastSyncAt))
    syncTimer.interval = wait
    if (!syncTimer.running || force) syncTimer.restart()
  }
  function _doSync() {
    if (!enforce || !helperUsable || uid < 0) return
    var ctx = _ctx()
    var res = Model.buildSpec(rules, ctx, conns, apps, ipCidrs, uid)
    res.spec.logNew = prefs.catchShort !== false        // ignored by helpers older than 1.2
    var routes = Model.compileRoutes(rules, defaultRoute, proxies, ctx, conns, apps, uid)
    if (routes && proxyCapable) {
      res.spec.proxy = routes
      proxyError = ""
    } else if (routes) {
      // An older helper would ignore the routes and the apps would go direct:
      // block what should be proxied until the helper is updated.
      var blocks = routes.rules.filter(function(e) { return e.verdict === "redirect" })
        .map(function(e) { var d = Object.assign({}, e, { verdict: "drop" }); delete d.port; return d })
      res.spec.rules = blocks.concat(res.spec.rules)
      if (routes.defaultPort !== null) res.spec.silentDeny = true
      proxyError = "Proxy routing needs citadel-helper " + minProxyHelper + " or newer (installed: "
                   + (helperVersion || "unknown") + "). Apps routed through a proxy are blocked until it is updated."
    } else {
      proxyError = ""
    }
    approx = res.approx
    var text = JSON.stringify(res.spec)
    if (text === _lastSpec && !_forceSync) return
    _forceSync = false
    _lastSpec = text
    _lastSyncAt = Date.now()
    enforceBusy = true
    _pendingRoutes = res.spec.proxy || null
    specFile.setText(text + "\n")
  }
  function _kill(targets) {
    if (!enforce || !helperUsable || !targets || !targets.length) return
    killFile.setText(JSON.stringify(targets) + "\n")
  }

  function _authHelp() {
    return root.inWheel
      ? "Authorization was cancelled or refused. Citadel's helper needs your approval (or the citadel-helper polkit rule)."
      : "Not authorized. Citadel's helper runs without a password only for the wheel group: "
        + "sudo usermod -aG wheel " + (Quickshell.env("USER") || "$USER") + ", then log out and back in."
  }

  function setEnforce(on) {
    if (on && !helperInstalled) { enforceError = "Install citadel-helper first: github.com/NeatOuk/citadel-helper"; return }
    if (on && helperOutdated) {
      enforceError = "citadel-helper " + helperVersion + " " + helperProblem + ". Update it before turning enforcement on."
      return
    }
    enforce = !!on
    save()
    if (enforce) {
      _lastSpec = ""
      if (helperUsable) _syncEnforcement(true)
      else verifyHelper()                        // version not known yet: check first
    }
    else {
      enforceBusy = true
      _run(["off"], function(code, out, err) {
        root.enforceBusy = false
        root.enforceActive = code !== 0 && root.enforceActive
        root.enforceError = code === 0 ? "" : (err || "could not turn off").trim().slice(0, 300)
      })
    }
  }
  function refreshEnforceStatus() {
    if (!helperInstalled) return
    _run(["status"], function(code, out) {
      try {
        var s = JSON.parse(out)
        root.enforceActive = !!s.active
        root.enforceDrops = Number(s.drops) || 0
        root.helperVersion = s.version || "1.1.0"
        root.helperLogging = !!s.logging
        if (root.helperOutdated && root.enforce) root.enforceActive = false
      } catch (e) {}
    })
  }

  // ------------------------------------------------- startup
  Process { id: ensureDirs; command: ["mkdir", "-p", root.stateDir + "/enforce"]
    onExited: stateFile.reload() }

  FileView {
    id: versionFile
    path: (Quickshell.env("OMARCHY_PATH") || "/usr/share/omarchy") + "/version"
    printErrors: false
    onLoaded: root.omarchyVersion = String(text()).trim()
  }
  Process {
    id: groupCheck
    command: ["id", "-Gn"]
    stdout: StdioCollector { id: groupsOut; waitForEnd: true }
    onExited: root.inWheel = String(groupsOut.text || "").split(/\s+/).indexOf("wheel") !== -1
  }

  // ------------------------------------------------- citadel-proxy (user process)
  readonly property string proxyBin: pluginDir + "/bin/citadel-proxy"
  Process {
    id: proxyProc
    command: [root.proxyBin]
    stdinEnabled: true
    stdout: SplitParser { onRead: function(line) { root._onProxyLine(line) } }
    onStarted: root._configureProxy()
    onExited: if (root.proxies.length) restartProxy.restart()
  }
  Timer { id: restartProxy; interval: 3000; onTriggered: if (root.proxies.length) proxyProc.running = true }

  function _configureProxy() {
    if (!loaded) return
    if (!proxies.length) { if (proxyProc.running) proxyProc.running = false; return }
    if (!proxyProc.running) { proxyProc.running = true; return }     // configured in onStarted
    proxyProc.write(JSON.stringify({ cmd: "config", checkEvery: 30, proxies: proxies }) + "\n")
  }
  function _onProxyLine(line) {
    var m
    try { m = JSON.parse(line) } catch (e) { return }
    if (m.type === "status") {
      var st = Object.assign({}, proxyStatus)
      st[m.id] = { ok: !!m.ok, ms: m.ms || 0, error: m.error || "", ts: Date.now() / 1000 }
      proxyStatus = st
    } else if (m.type === "check") {
      var ck = Object.assign({}, proxyCheck)
      ck[m.id] = { ok: !!m.ok, ms: m.ms || 0, error: m.error || "", ts: Date.now() / 1000 }
      proxyCheck = ck
    } else if (m.type === "error") {
      var pf = {}
      for (var fk in _proxyFailed) if (_proxyFailed[fk] > now - 60) pf[fk] = _proxyFailed[fk]
      pf[m.dst + "|" + m.port] = now
      _proxyFailed = pf
      var px = proxies.filter(function(x) { return x.id === m.id })[0]
      var name = px ? px.name : m.id
      var entry = { ts: Date.now() / 1000, proxy: name, dst: m.dst, port: m.port, error: m.error }
      // merge repeats of the same proxy + destination within a minute
      var last = proxyLog[0]
      if (last && last.proxy === name && last.dst === m.dst && entry.ts - last.ts < 60) return
      proxyLog = [entry].concat(proxyLog).slice(0, 50)
      _log([{ ts: now, app: "via " + name, exe: "", via: "", dest: m.dst, ip: m.dst, port: m.port, cc: "",
              verdict: "deny", source: "proxy " + name + " unreachable" }])
    } else if (m.type === "stats") {
      proxyCarried = proxyCarried.filter(function(x) { return x.ts > now - 300 }).concat([{ ts: now, counts: m.counts || {} }])
    } else if (m.type === "log") console.warn("[citadel] proxy:", m.msg)
  }

  // secret-tool keeps "user:password" in the desktop keyring
  Process { id: secretStore; stdinEnabled: true; property string secret: ""
    onStarted: { write(secret); secret = ""; stdinEnabled = false }
    onExited: { stdinEnabled = true; root._configureProxy() } }
  function _storeSecret(id, name, user, password) {
    secretStore.secret = user + ":" + password
    secretStore.command = ["secret-tool", "store", "--label=Citadel proxy " + name, "citadel-proxy", id]
    secretStore.running = true
  }

  // fields: {id?, name, type, host, port, verifyTls}; user/password optional
  // ("" keeps the stored login when editing, null removes it)
  function saveProxy(fields, user, password) {
    var type = ["http", "https", "socks5"].indexOf(fields.type) !== -1 ? fields.type : "http"
    var port = Math.round(Number(fields.port))
    var host = String(fields.host || "").trim()
    if (!host || !(port >= 1 && port <= 65535)) return "Enter a host and a port (1–65535)."
    var old = proxies.filter(function(x) { return x.id === fields.id })[0]
    var id = old ? old.id : "px" + Date.now().toString(36)
    var auth = user === null ? false : (user ? true : !!(old && old.auth))
    var px = { id: id, name: String(fields.name || host).trim(), type: type, host: host, port: port,
               listen: old ? old.listen : Model.freeListenPort(proxies), auth: auth,
               verifyTls: fields.verifyTls !== false }
    if (!px.listen) return "Too many proxies."
    proxies = old ? proxies.map(function(x) { return x.id === id ? px : x }) : proxies.concat([px])
    save()
    _sendConfig()
    if (user) _storeSecret(id, px.name, user, password || "")
    else if (user === null) Quickshell.execDetached(["secret-tool", "clear", "citadel-proxy", id])
    _configureProxy()
    if (enforce) _syncEnforcement(true)
    return ""
  }
  function removeProxy(id) {
    proxies = proxies.filter(function(x) { return x.id !== id })
    var st = Object.assign({}, proxyStatus); delete st[id]; proxyStatus = st
    var ck = Object.assign({}, proxyCheck); delete ck[id]; proxyCheck = ck
    if (defaultRoute === id) defaultRoute = "direct"
    Quickshell.execDetached(["secret-tool", "clear", "citadel-proxy", id])
    save(); _configureProxy()
    if (enforce) _syncEnforcement(true)
  }
  function checkProxy(id) {
    var ck = Object.assign({}, proxyCheck); ck[id] = { pending: true }; proxyCheck = ck
    if (proxyProc.running) proxyProc.write(JSON.stringify({ cmd: "check", id: id }) + "\n")
  }
  function setDefaultRoute(route) {
    defaultRoute = route === "direct" || proxies.some(function(x) { return x.id === route }) ? route : "direct"
    save()
    if (enforce) _syncEnforcement(true)
  }
  function proxyName(route) {
    if (!route || route === "direct") return ""
    var px = proxies.filter(function(x) { return x.id === route })[0]
    return px ? px.name : "missing proxy"
  }
  function proxyCarried5m(id) {
    var n = 0
    proxyCarried.forEach(function(x) { if (x.ts > now - 300) n += Number(x.counts[id] || 0) })
    return n
  }
  function routeOf(conn) { return Model.routeFor(conn, rules, _ctx(), defaultRoute, proxies) }

  // ------------------------------------------------- explain (the user's own agent)
  // Who answers: the custom command from Settings, else the user's Omarchy
  // default agent. Nothing runs until Explain is pressed.
  FileView {
    id: agentFile
    path: root.home + "/.config/omarchy/defaults/agent"
    watchChanges: true
    printErrors: false
    onFileChanged: reload()
  }
  readonly property string defaultAgent: String(agentFile.text() || "").trim()
  readonly property bool explainCustom: String(prefs.explainCommand || "").trim() !== ""
  readonly property string explainAgent: explainCustom ? "custom command" : defaultAgent
  readonly property bool explainAvailable: explainAgent !== ""
  property var explanations: ({})           // explainKey -> {state, result, agent, model, cached, error}
  property var _explainQueue: []            // [{key, req}]
  property var explainTestResult: ({})

  function explainKey(conn) {
    return (conn.exe || conn.app || "?") + "|" + (conn.host || conn.raddr || "") + "|" + (conn.rport || "")
  }
  function explanationOf(conn) { return conn ? explanations[explainKey(conn)] || null : null }
  function _setExplanation(key, value) {
    var e = Object.assign({}, explanations); e[key] = value; explanations = e
    // the user is reading about it: restart that request's countdown
    alerts = alerts.map(function(a) {
      return root.explainKey(a.conn) === key ? Object.assign({}, a, { firstSeen: root.now }) : a
    })
  }
  function explain(conn, fresh) {
    if (!conn || !explainAvailable) return
    var key = explainKey(conn)
    var cur = explanations[key]
    if (cur && cur.state === "pending") return
    _setExplanation(key, { state: "pending", agent: explainAgent })
    // the command line is masked by the monitor; only what's needed leaves the machine
    var c = { app: conn.app || "", exe: conn.exe || "", via: conn.via || "", cmd: conn.cmd || "",
              host: conn.host || "", raddr: conn.raddr || "", rport: conn.rport || 0, proto: conn.proto || "tcp",
              cc: conn.cc || "", org: conn.org || "" }
    _explainQueue = _explainQueue.concat([{ key: key, req: { conn: c, fresh: !!fresh } }])
    _explainNext()
  }
  function testExplain() {
    explainTestResult = { state: "pending", agent: explainAgent }
    _explainQueue = _explainQueue.concat([{ key: "", test: true, req: { test: true } }])
    _explainNext()
  }
  function _explainNext() {
    if (explainProc.running || _explainQueue.length === 0) return
    var job = _explainQueue[0]
    _explainQueue = _explainQueue.slice(1)
    job.req.prefs = { explainCommand: prefs.explainCommand || "", explainModel: prefs.explainModel || "" }
    explainProc.job = job
    explainProc.input = JSON.stringify(job.req)
    explainProc.command = ["python3", root.explainBin]
    explainProc.running = true
  }
  function _explainDone(job, text) {
    var r = null
    var lines = String(text || "").trim().split("\n")
    try { r = JSON.parse(lines[lines.length - 1]) } catch (e) { r = null }
    var v = !r ? { state: "error", code: "failed", error: "Citadel explain gave no answer.", agent: explainAgent }
          : r.ok ? { state: "done", result: r.result, agent: r.agent, model: r.model || "", cached: !!r.cached }
          : { state: "error", code: r.code || "failed", error: r.error || "failed", agent: r.agent || explainAgent }
    if (job.test) explainTestResult = v
    else _setExplanation(job.key, v)
  }
  Process {
    id: explainProc
    property var job: null
    property string input: ""
    stdinEnabled: true
    stdout: StdioCollector { id: explainOut; waitForEnd: true }
    onStarted: { write(input); input = ""; stdinEnabled = false }
    onExited: {
      stdinEnabled = true
      var j = job; job = null
      if (j) root._explainDone(j, explainOut.text)
      root._explainNext()
    }
  }

  Component.onCompleted: {
    ensureDirs.running = true
    helperCheck.running = true
    groupCheck.running = true
    monitor.running = true
  }
}
