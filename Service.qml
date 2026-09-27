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
                         retentionDays: 30, notify: true, modeMinutes: 0, catchShort: true })
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
  property var resolved: ({})
  property var stats: ({ series: [], topAppsToday: [], topHostsToday: [], countriesToday: [], topApps7d: [] })
  property var listStatus: ({})
  property var ipCidrs: []
  property var geoip: ({ installed: false, error: "" })
  property var approx: ({})
  property var protectedPids: ({})          // Citadel's monitor and the shell hosting it
  property var recentShort: []              // short connections the poll missed (newest first)
  property var kernelLog: ({ running: false, error: "", seen: 0 })
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
  readonly property bool helperOutdated: helperVersion !== "" && _versionLess(helperVersion, minHelper)
  function _versionLess(a, b) {
    var x = String(a).split("."), y = String(b).split(".")
    for (var i = 0; i < 3; i++) {
      var d = (Number(x[i]) || 0) - (Number(y[i]) || 0)
      if (d !== 0) return d < 0
    }
    return false
  }
  property string _lastSpec: ""

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
      decisionLog: root.decisionLog.slice(0, 300), prefs: root.prefs
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
      var d = Model.decide(c, rules, ctx)
      // binary changed since the user allowed it -> ask again
      if (d.source === "rule" && d.verdict === "allow" && d.rule.exeHash && c.exe && apps[c.exe]) {
        var h = (apps[c.exe].trust || {}).hash
        if (h && h !== d.rule.exeHash) d = { verdict: "prompt", source: "changed", rule: d.rule }
      }
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
        var sd = Model.decide(sc, rules, ctx)
        recent.push({ conn: sc, decision: sd })
        if (first) continue
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

  // ------------------------------------------------- alerts
  function _queueAlert(queue, conn, d) {
    var key = Model.alertKey(conn)
    for (var i = 0; i < queue.length; i++) if (queue[i].key === key) return
    var info = apps[conn.exe] || null
    queue.push({ key: key, conn: conn, firstSeen: now, changed: d.source === "changed", short: !!conn.short,
                 trust: info ? info.trust : { level: "unknown" }, hasOwnScope: !!(info && info.owned && info.owned.length) })
    if (prefs.notify !== false) _notify(conn, d.source === "changed")
  }

  // Answer the oldest (or given) alert.
  // action: allow|deny ; scope: hostPort|host|app ; duration: once|untilQuit|forever
  // viaScoped: the policy only covers the app when started by the same launcher
  function answer(key, action, scope, duration, source, viaScoped) {
    var alert = null
    for (var i = 0; i < alerts.length; i++) if (alerts[i].key === key) { alert = alerts[i]; break }
    if (!alert) return
    if (duration === "once") {
      var s = Object.assign({}, session)
      s[key] = action
      session = s
    } else {
      var info = apps[alert.conn.exe] || null
      // replace a stale rule for a changed binary
      if (alert.changed) rules = rules.filter(function(r) { return !(r.app === alert.conn.exe && r.exeHash) })
      addRule(Model.ruleFromAlert(alert, action, scope, duration, "*", info, viaScoped === true), true)
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

  Process { id: notifyProc; stdout: StdioCollector { id: notifyOut; waitForEnd: true }
    onExited: if (String(notifyOut.text || "").indexOf("default") !== -1) root.openRequested("gate") }
  function _notify(conn, changed) {
    var title = changed ? "Changed app at the gate" : "At the gate"
    var body = Model.appWithOrigin(conn) + " → " + Model.destLabel(conn) + ":" + conn.rport
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
      if (!was && root.helperInstalled) {
        if (root.enforceError.indexOf("helper") !== -1) root.enforceError = ""
        if (root.enforce) root._syncEnforcement(true)
      }
    }
  }
  // pick the helper up as soon as the package is installed
  Timer { interval: 10000; repeat: true; running: !root.helperInstalled; onTriggered: helperCheck.running = true }

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
        if (root.helperVersion === "") root.refreshEnforceStatus()
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
    if (!enforce || !helperInstalled || uid < 0) return
    var res = Model.buildSpec(rules, _ctx(), conns, apps, ipCidrs, uid)
    res.spec.logNew = prefs.catchShort !== false        // ignored by helpers older than 1.2
    approx = res.approx
    var text = JSON.stringify(res.spec)
    if (text === _lastSpec && !_forceSync) return
    _forceSync = false
    _lastSpec = text
    _lastSyncAt = Date.now()
    enforceBusy = true
    specFile.setText(text + "\n")
  }
  function _kill(targets) {
    if (!enforce || !helperInstalled || !targets || !targets.length) return
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
    enforce = !!on
    save()
    if (enforce) { _lastSpec = ""; _syncEnforcement(true) }
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

  Component.onCompleted: {
    ensureDirs.running = true
    helperCheck.running = true
    groupCheck.running = true
    monitor.running = true
  }
}
