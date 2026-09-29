import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// One request at the gate: who wants out, where to, and three quick
// verdicts. "Adjust" reveals what Block / Always allow cover and for how long.
// An app that updated to a new path asks once instead: keep its policies?
Column {
  id: root
  property var p: null          // panel (colors, fonts)
  property var s: null          // service
  property var alert: null
  property bool adjusting: false
  property string scope: "host"            // hostPort | host | app
  property string duration: "forever"      // forever | untilQuit
  // cover the app only when started by the same launcher (script / program)
  property bool viaScoped: viaDefault
  property string route: "default"                  // for "Always allow"

  readonly property var conn: alert ? alert.conn : ({})
  readonly property var tr: alert ? (alert.trust || {}) : ({})
  readonly property var ex: s && alert ? s.explanationOf(conn) : null
  readonly property int remaining: alert && s && Number(s.prefs.alertTimeout) > 0
    ? Math.max(0, Math.round(Number(s.prefs.alertTimeout) - (s.now - alert.firstSeen))) : -1
  readonly property bool updated: !!(alert && alert.updatedFrom)
  readonly property bool hasVia: !!(conn && conn.via)
  // a launcher worth scoping to: scripts and programs, not "you, in a terminal"
  readonly property bool viaDefault: hasVia && conn.viaKind !== "terminal"
  readonly property string scopeText: (hasVia && viaScoped ? Model.appLabel(conn) + " " + Model.originLabel(conn) + ": " : "")
    + (scope === "app" ? "every host"
       : scope === "hostPort" ? Model.destLabel(conn) + " on port " + conn.rport : Model.destLabel(conn))

  spacing: Style.space(6)
  onAlertChanged: { adjusting = false; scope = "host"; duration = "forever"; viaScoped = viaDefault; route = "default" }

  function integrity(t) {
    var l = t.level || "unknown"
    if (l === "verified") return { text: "integrity ✓" + (t.pkg ? " " + t.pkg : ""), bad: false, warn: false }
    if (l === "unpackaged") return { text: "integrity: not packaged", bad: false, warn: true }
    if (l === "modified") return { text: "integrity ✕ modified", bad: true, warn: false }
    if (l === "suspicious") return { text: "integrity ✕ " + (t.reason || "suspicious"), bad: true, warn: false }
    return { text: "integrity: unknown", bad: false, warn: true }
  }
  // "2.1.281 → 2.1.283": the parts of the two paths that differ
  function versionChange(a, b) {
    var x = String(a || "").split("/"), y = String(b || "").split("/"), out = []
    if (x.length !== y.length) return ""
    for (var i = 0; i < x.length; i++)
      if (x[i] !== y[i]) out.push(x[i].replace(/^[0-9a-z]{32}-/, "") + " → " + y[i].replace(/^[0-9a-z]{32}-/, ""))
    return out.join(" ")
  }
  function verdict(action, duration) {
    s.answer(alert.key, action, scope, duration, "", hasVia && viaScoped, route)
  }

  // who
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl {
      p: root.p
      Layout.fillWidth: true
      text: Model.appLabel(root.conn)
      strong: true
      font.pixelSize: Style.font.body
    }
    Lbl {
      p: root.p
      readonly property var ig: root.integrity(root.tr)
      text: ig.text
      color: ig.bad ? root.p.urgent : ig.warn ? root.p.dim : root.p.foreground
      font.pixelSize: Style.font.caption
    }
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: root.hasVia
    text: Model.originLabel(root.conn)
          + (root.conn.viaKind === "script" ? "  (script)" : root.conn.viaKind === "terminal" ? "  (you, in a terminal)" : "")
    font.pixelSize: Style.font.bodySmall
    elide: Text.ElideMiddle
  }
  Lbl {
    p: root.p
    width: parent.width
    dim: true
    text: root.conn.cmd || root.conn.exe || "(system process)"
    font.pixelSize: Style.font.caption
    elide: Text.ElideRight          // middle-elide does not work on wrapped text
    maximumLineCount: 2
    wrapMode: Text.WrapAnywhere
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: root.adjusting && (root.conn.chain || []).length > 1
    dim: true
    text: "chain: " + [Model.appLabel(root.conn)].concat(root.conn.chain || []).join(" ← ")
    font.pixelSize: Style.font.caption
    elide: Text.ElideMiddle
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: !!(root.alert && root.alert.changed)
    color: root.p.urgent
    text: "Its program changed since you let it through. Make sure the update is expected."
    wrapMode: Text.WordWrap
    maximumLineCount: 3
  }

  // an update to a new path
  Lbl {
    p: root.p
    width: parent.width
    visible: root.updated
    text: "Updated " + root.versionChange(root.alert ? root.alert.updatedFrom : "", root.conn.exe)
          + ". Its " + (root.alert && root.alert.policies === 1 ? "policy is" : (root.alert ? root.alert.policies : 0) + " policies are")
          + " for the old version. Keep them for this one, or answer its connections one by one like a new app's."
    wrapMode: Text.WordWrap
    maximumLineCount: 4
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(6)
    visible: root.updated
    Button {
      Layout.fillWidth: true
      text: "Ask as a new app"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      tooltipText: "Its connections come to the gate one by one"
      onClicked: root.s.answer(root.alert.key, "new", "app", "forever", "", false, "default")
    }
    Button {
      Layout.fillWidth: true
      text: "Keep its policies"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      selected: true
      tooltipText: "Move the old version's policies to this one"
      onClicked: root.s.answer(root.alert.key, "keep", "app", "forever", "", false, "default")
    }
  }

  Lbl {
    p: root.p
    width: parent.width
    visible: !!root.conn.short
    dim: true
    wrapMode: Text.WordWrap
    maximumLineCount: 3
    font.pixelSize: Style.font.caption
    text: "This connection already finished; your verdict applies from the next one."
          + (root.conn.confidence === "likely" ? " Matched by timing, so check the app is right." : "")
  }

  // where
  Rectangle {
    visible: !root.updated
    width: parent.width
    height: dest.implicitHeight + Style.space(12)
    color: Qt.rgba(root.p.foreground.r, root.p.foreground.g, root.p.foreground.b, 0.05)
    radius: Style.cornerRadius
    Column {
      id: dest
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(8)
      anchors.rightMargin: Style.space(8)
      spacing: Style.space(1)
      Lbl {
        p: root.p
        width: parent.width
        text: "→  " + Model.destLabel(root.conn)
        strong: true
        font.pixelSize: Style.font.body
        elide: Text.ElideMiddle
      }
      Lbl {
        p: root.p
        width: parent.width
        dim: true
        font.pixelSize: Style.font.caption
        text: (root.conn.cc ? Model.flag(root.conn.cc) + " " + root.conn.cc + "   " : "")
              + (root.conn.host ? root.conn.raddr + "   " : "")
              + String(root.conn.proto || "").toUpperCase() + " " + root.conn.rport
              + (Model.portName(root.conn.rport) ? " · " + Model.portName(root.conn.rport) : "")
      }
      Lbl {
        p: root.p
        width: parent.width
        visible: !!root.conn.org
        dim: true
        font.pixelSize: Style.font.caption
        text: "Owner: " + (root.conn.org || "")
        elide: Text.ElideRight
      }
    }
  }

  // explain: asks the user's own agent (on demand, cached)
  Column {
    width: parent.width
    spacing: Style.space(2)
    visible: !!root.s && !root.updated
    RowLayout {
      width: parent.width
      spacing: Style.space(8)
      visible: root.s.explainAvailable
      LinkButton {
        p: root.p
        visible: !root.ex || root.ex.state !== "pending"
        text: !root.ex ? "Explain" : "Ask again"
        onClicked: root.s.explain(root.conn, !!root.ex)
      }
      Lbl {
        p: root.p
        visible: !!root.ex && root.ex.state === "pending"
        dim: true
        text: "Asking " + (root.ex ? root.ex.agent : "") + "…"
        font.pixelSize: Style.font.caption
      }
      Lbl {
        p: root.p
        Layout.fillWidth: true
        visible: !root.ex
        dim: true
        text: "Sends the app, host and masked command to " + root.s.explainAgent
        font.pixelSize: Style.font.caption
        elide: Text.ElideRight
      }
    }
    Lbl {
      p: root.p
      width: parent.width
      visible: !root.s.explainAvailable
      dim: true
      wrapMode: Text.WordWrap
      maximumLineCount: 2
      font.pixelSize: Style.font.caption
      text: "Explain needs an Omarchy default agent (omarchy agent --pick) or a custom command in Settings."
    }
    Lbl {
      p: root.p
      width: parent.width
      visible: !!root.ex && root.ex.state === "error"
      color: root.p.urgent
      wrapMode: Text.WordWrap
      maximumLineCount: 3
      font.pixelSize: Style.font.caption
      text: root.ex && root.ex.error ? root.ex.error : ""
    }
    Lbl {
      p: root.p
      width: parent.width
      visible: !!root.ex && root.ex.state === "done"
      wrapMode: Text.WordWrap
      maximumLineCount: 4
      font.pixelSize: Style.font.bodySmall
      readonly property var r: root.ex && root.ex.result ? root.ex.result : ({})
      text: (r.service && r.service !== r.company ? r.service + " · " : "") + (r.company || "")
            + (r.purpose ? " — " + r.purpose : "") + (r.category ? " (" + r.category + ")" : "")
    }
    Lbl {
      p: root.p
      width: parent.width
      visible: !!root.ex && root.ex.state === "done"
      readonly property var r: root.ex && root.ex.result ? root.ex.result : ({})
      color: r.suggestion === "block" ? root.p.urgent : root.p.foreground
      wrapMode: Text.WordWrap
      maximumLineCount: 3
      font.pixelSize: Style.font.caption
      text: "Suggests: " + (r.suggestion === "either" ? "your call" : r.suggestion === "block" ? "Block" : "Allow")
            + (r.why ? " — " + r.why : "") + "   risk " + (r.risk || "?")
            + (r.confidence === "low" ? " · unsure" : "")
    }
    Lbl {
      p: root.p
      width: parent.width
      visible: !!root.ex && root.ex.state === "done"
      dim: true
      font.pixelSize: Style.font.caption
      elide: Text.ElideRight
      text: root.ex ? "by " + root.ex.agent + (root.ex.model ? " · " + root.ex.model : "") + (root.ex.cached ? " · saved answer" : "") : ""
    }
  }

  // verdicts
  RowLayout {
    visible: !root.updated
    width: parent.width
    spacing: Style.space(6)
    Button {
      Layout.fillWidth: true
      text: "Block"
      foreground: root.p.urgent
      fontSize: Style.font.bodySmall
      bordered: true
      tooltipText: "Block " + root.scopeText + (root.duration === "untilQuit" ? " until the app quits" : " from now on")
      onClicked: root.verdict("deny", root.duration)
    }
    Button {
      Layout.fillWidth: true
      text: "Allow once"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      tooltipText: "Let this connection through; ask again next time"
      onClicked: root.verdict("allow", "once")
    }
    Button {
      Layout.fillWidth: true
      text: "Always allow"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      selected: true
      tooltipText: "Allow " + root.scopeText + (root.duration === "untilQuit" ? " until the app quits" : " from now on")
      onClicked: root.verdict("allow", root.duration)
    }
  }

  RowLayout {
    width: parent.width
    LinkButton {
      p: root.p
      visible: !root.updated
      text: root.adjusting ? "Adjust ▾" : "Adjust ▸"
      onClicked: root.adjusting = !root.adjusting
    }
    Lbl {
      p: root.p
      Layout.fillWidth: true
      horizontalAlignment: Text.AlignRight
      dim: true
      visible: root.remaining >= 0
      text: root.updated ? "asks as a new app in " + root.remaining + "s"
            : (root.s && root.s.prefs.alertDefault === "deny" ? "blocks" : "lets through") + " once in " + root.remaining + "s"
      font.pixelSize: Style.font.caption
    }
  }

  // adjust: what Block / Always allow cover
  Column {
    visible: root.adjusting && !root.updated
    width: parent.width
    spacing: Style.space(5)
    Lbl { p: root.p; dim: true; text: "Covers"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      options: [{ value: "hostPort", label: "This port" }, { value: "host", label: "This host" },
                { value: "app", label: "Every host" }]
      value: root.scope
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.scope = v }
    }
    Lbl { p: root.p; dim: true; visible: root.hasVia; text: "Started by"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      visible: root.hasVia
      options: [{ value: "via", label: "Only " + (root.conn.viaKind === "terminal" ? "in " : "via ") + (root.conn.via || "") },
                { value: "any", label: "However it starts" }]
      value: root.viaScoped ? "via" : "any"
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.viaScoped = v === "via" }
    }
    Lbl { p: root.p; dim: true; visible: root.s.proxies.length > 0; text: "Always allow routes it"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      visible: root.s.proxies.length > 0
      options: [{ value: "default", label: root.s.defaultRoute === "direct" ? "Default (direct)" : "Default (" + root.s.proxyName(root.s.defaultRoute) + ")" },
                { value: "direct", label: "Direct" }]
               .concat(root.s.proxies.map(function(x) { return { value: x.id, label: "via " + x.name } }))
      value: root.route
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.route = v }
    }
    Lbl { p: root.p; dim: true; text: "Lasts"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      options: [{ value: "forever", label: "From now on" }, { value: "untilQuit", label: "Until the app quits" }]
      value: root.duration
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.duration = v }
    }
  }
}
