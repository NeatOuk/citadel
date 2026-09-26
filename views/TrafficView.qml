import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// Traffic: live connections grouped by app. Click an app to expand it;
// Allow / Block create policies for the whole app or one destination.
Column {
  id: root
  property var p: null
  property var s: null
  property bool showSystem: false
  property var expanded: ({})

  spacing: Style.space(8)

  function statusColor(d) {
    if (!d) return p.dim
    if (d.verdict === "deny") return p.urgent
    if (d.verdict === "prompt") return Color.accent
    if (d.verdict === "system") return Qt.darker(p.dim, 1.4)
    return p.foreground
  }
  function statusText(d) {
    if (!d) return ""
    if (d.verdict === "system") return "system"
    if (d.verdict === "prompt") return d.source === "changed" ? "changed app, at the gate" : "no verdict yet"
    var v = d.verdict === "deny" ? "blocked" : "allowed"
    if (d.source === "rule") return v + " by policy"
    if (d.source === "blocklist") return "blocked by feed " + (d.list || "")
    if (d.source === "once") return v + " once"
    if (d.source === "silent") return v + (d.verdict === "deny" ? " (lockdown)" : " (open mode)")
    return v
  }
  function toggle(key) {
    var e = Object.assign({}, expanded)
    e[key] = !e[key]
    expanded = e
  }

  // ---------------------------------------------------------------- stats
  GridLayout {
    width: parent.width
    columns: 4
    columnSpacing: Style.space(10)
    Repeater {
      model: [
        { label: "LIVE", value: String(root.s.totals.connections) },
        { label: "APPS", value: String(root.s.totals.apps) },
        { label: "↓ DOWN", value: Model.humanRate(root.s.rate.down) },
        { label: "↑ UP", value: Model.humanRate(root.s.rate.up) }
      ]
      delegate: Column {
        required property var modelData
        Layout.fillWidth: true
        spacing: Style.space(2)
        Lbl { p: root.p; dim: true; text: modelData.label; font.pixelSize: Style.font.caption; font.letterSpacing: 1; strong: true }
        Lbl { p: root.p; text: modelData.value; font.pixelSize: Style.font.title; strong: true }
      }
    }
  }

  RowLayout {
    width: parent.width
    Lbl {
      p: root.p
      Layout.fillWidth: true
      dim: true
      text: !root.s.monitorUp ? "The watch is starting…"
          : root.s.totals.denied > 0 ? root.s.totals.denied + " connection(s) blocked right now" : "Click an app to see where it connects"
      color: root.s.monitorError !== "" ? root.p.urgent : root.p.dim
    }
    LinkButton {
      p: root.p
      text: root.showSystem ? "Hide system services" : "Show system services"
      onClicked: root.showSystem = !root.showSystem
    }
  }

  // ---------------------------------------------------------------- groups
  Repeater {
    model: root.s.groups.filter(function(g) { return root.showSystem || !g.system })
    delegate: Column {
      id: grp
      required property var modelData
      readonly property bool open: !!root.expanded[modelData.key]
      readonly property var appInfo: root.s.apps[modelData.exe] || null
      readonly property var appRule: {
        var rs = root.s.rules
        for (var i = 0; i < rs.length; i++)
          if (rs[i].app === modelData.exe && rs[i].host === "*" && rs[i].port === "*"
              && (rs[i].via || "*") === (modelData.viaId || "*")
              && (rs[i].profile === "*" || rs[i].profile === root.s.activeProfile)) return rs[i]
        return null
      }
      width: root.width
      spacing: Style.space(3)

      Item {
        width: parent.width
        height: headRow.implicitHeight + Style.space(6)
        MouseArea {
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          onClicked: root.toggle(grp.modelData.key)
        }
        RowLayout {
          id: headRow
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(8)
          Rectangle {
            width: Style.space(7); height: width; radius: width / 2
            color: grp.modelData.denied > 0 ? root.p.urgent
                 : grp.modelData.prompts > 0 ? Color.accent
                 : grp.modelData.system ? Qt.darker(root.p.dim, 1.4) : root.p.foreground
          }
          Lbl {
            p: root.p
            Layout.fillWidth: true
            text: (grp.open ? "▾ " : "▸ ") + grp.modelData.app
                  + (grp.modelData.via ? (grp.modelData.viaKind === "terminal" ? "  in " : "  via ") + grp.modelData.via : "")
                  + (grp.modelData.system ? "  (system)" : "")
            strong: true
          }
          Lbl {
            p: root.p
            dim: true
            text: grp.modelData.conns.length + " · ↓" + Model.humanRate(grp.modelData.downRate)
                  + " ↑" + Model.humanRate(grp.modelData.upRate)
            font.pixelSize: Style.font.caption
          }
          LinkButton {
            p: root.p
            visible: !grp.modelData.system && !!grp.modelData.exe
            text: grp.appRule && grp.appRule.action === "allow" ? "Allowed ✓" : "Allow app"
            onClicked: grp.appRule && grp.appRule.action === "allow"
              ? root.s.removeRule(grp.appRule.id) : root.s.allowApp(grp.modelData.exe, grp.modelData.viaId)
          }
          LinkButton {
            p: root.p
            danger: true
            visible: !grp.modelData.system && !!grp.modelData.exe
            text: grp.appRule && grp.appRule.action === "deny" ? "Blocked ✕" : "Block app"
            onClicked: grp.appRule && grp.appRule.action === "deny"
              ? root.s.removeRule(grp.appRule.id) : root.s.denyApp(grp.modelData.exe, grp.modelData.viaId)
          }
        }
      }

      Lbl {
        p: root.p
        visible: grp.open && !!grp.modelData.exe
        width: parent.width
        leftPadding: Style.space(15)
        dim: true
        font.pixelSize: Style.font.caption
        elide: Text.ElideMiddle
        text: grp.modelData.exe + (grp.appInfo && grp.appInfo.trust
              ? "   ·   integrity " + (grp.appInfo.trust.level || "") + (grp.appInfo.trust.pkg ? " (" + grp.appInfo.trust.pkg + ")" : "") : "")
      }

      Repeater {
        model: grp.open ? grp.modelData.conns : []
        delegate: RowLayout {
          required property var modelData
          readonly property var d: root.s.decisions[modelData.key]
          width: grp.width
          spacing: Style.space(6)
          Item { width: Style.space(9) }
          Rectangle {
            width: Style.space(5); height: width; radius: width / 2
            color: root.statusColor(parent.d)
          }
          Column {
            Layout.fillWidth: true
            spacing: 0
            Lbl {
              p: root.p
              width: parent.width
              text: (modelData.cc ? Model.flag(modelData.cc) + " " : "") + Model.destLabel(modelData)
                    + ":" + modelData.rport
              elide: Text.ElideMiddle
            }
            Lbl {
              p: root.p
              width: parent.width
              dim: true
              font.pixelSize: Style.font.caption
              text: modelData.proto.toUpperCase()
                    + (modelData.state === "syn-sent" ? " · connecting" : "")
                    + (modelData.host ? " · " + modelData.raddr : "")
                    + " · ↓" + Model.humanBytes(modelData.down) + " ↑" + Model.humanBytes(modelData.up)
                    + " · " + root.statusText(parent.parent.d)
            }
            Lbl {
              p: root.p
              width: parent.width
              visible: !!modelData.cmd && !!grp.modelData.viaId
              dim: true
              font.pixelSize: Style.font.caption
              elide: Text.ElideMiddle
              text: "$ " + modelData.cmd
            }
          }
          LinkButton {
            p: root.p
            visible: !modelData.system
            text: "Allow"
            onClicked: root.s.allowConn(modelData)
          }
          LinkButton {
            p: root.p
            danger: true
            visible: !modelData.system
            text: "Block"
            onClicked: root.s.denyConn(modelData)
          }
        }
      }
    }
  }

  // ---------------------------------------------------------------- just now
  // Connections that started and ended between two polls, caught through the
  // kernel log (citadel-helper 1.2+ with "Catch short connections" on).
  PanelSeparator { visible: root.s.recentShort.length > 0; foreground: root.p.foreground }
  RowLayout {
    width: parent.width
    visible: root.s.recentShort.length > 0
    PanelSectionHeader { text: "JUST NOW · SHORT CONNECTIONS"; foreground: root.p.foreground; fontFamily: root.p.fontFamily; Layout.fillWidth: true }
    Lbl { p: root.p; dim: true; text: root.s.recentShort.length + " caught"; font.pixelSize: Style.font.caption }
  }
  Repeater {
    model: root.s.recentShort.slice(0, 12)
    delegate: RowLayout {
      required property var modelData
      readonly property var c: modelData.conn
      width: root.width
      spacing: Style.space(6)
      Rectangle {
        width: Style.space(5); height: width; radius: width / 2
        color: root.statusColor(modelData.decision)
      }
      Column {
        Layout.fillWidth: true
        spacing: 0
        Lbl {
          p: root.p
          width: parent.width
          text: Model.appWithOrigin(parent.parent.c) + "  →  " + (parent.parent.c.cc ? Model.flag(parent.parent.c.cc) + " " : "")
                + Model.destLabel(parent.parent.c) + ":" + parent.parent.c.rport
          elide: Text.ElideMiddle
        }
        Lbl {
          p: root.p
          width: parent.width
          dim: true
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
          text: Model.clock(parent.parent.c.ts) + " · " + parent.parent.c.proto.toUpperCase()
                + " · " + (parent.parent.c.confidence === "matched" ? "matched by command"
                           : parent.parent.c.confidence === "likely" ? "likely (timing)"
                           : "app unclear" + (parent.parent.c.guess ? " (maybe " + parent.parent.c.guess + ")" : ""))
                + " · " + root.statusText(modelData.decision)
                + (parent.parent.c.cmd ? "  $ " + parent.parent.c.cmd : "")
        }
      }
      Lbl {
        p: root.p
        visible: (modelData.count || 1) > 1
        dim: true
        text: "×" + modelData.count
        font.pixelSize: Style.font.caption
      }
      // verdicts only when Citadel is confident which app it was
      LinkButton {
        p: root.p
        visible: (parent.c.confidence === "matched" || parent.c.confidence === "likely") && !!parent.c.exe
        text: "Allow"
        onClicked: root.s.allowConn(parent.c)
      }
      LinkButton {
        p: root.p
        danger: true
        visible: (parent.c.confidence === "matched" || parent.c.confidence === "likely") && !!parent.c.exe
        text: "Block"
        onClicked: root.s.denyConn(parent.c)
      }
    }
  }

  Lbl {
    p: root.p
    visible: root.s.groups.length === 0
    dim: true
    text: root.s.monitorUp ? "Nothing is leaving right now." : "The watch is starting…"
  }
}
