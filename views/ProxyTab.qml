import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// Traffic → Proxy: per proxy, its health, what it carries right now, the
// policies that route through it, and recent failures.
Column {
  id: root
  property var p: null
  property var s: null
  property var view: null           // TrafficView (row colours and verdict text)

  spacing: Style.space(10)

  // live connections grouped by the proxy that carries them
  readonly property var byProxy: {
    var out = {}
    ;(s.conns || []).forEach(function(c) {
      var r = s.routeOf(c)
      if (!r) return
      ;(out[r.id] = out[r.id] || []).push(c)
    })
    return out
  }

  Repeater {
    model: root.s.proxies
    delegate: Column {
      id: px
      required property var modelData
      readonly property var st: root.s.proxyStatus[modelData.id] || null
      readonly property var ck: root.s.proxyCheck[modelData.id] || null
      readonly property var live: root.byProxy[modelData.id] || []
      readonly property var routedBy: root.s.rules.filter(function(r) { return r.action === "allow" && r.route === px.modelData.id })
      readonly property var failures: root.s.proxyLog.filter(function(e) { return e.proxy === px.modelData.name }).slice(0, 10)
      width: root.width
      spacing: Style.space(4)

      // header: health and Check
      RowLayout {
        width: parent.width
        spacing: Style.space(8)
        Rectangle {
          width: Style.space(8); height: width; radius: width / 2
          color: !px.st ? root.p.dim : px.st.ok ? root.p.foreground : root.p.urgent
        }
        Lbl { p: root.p; text: px.modelData.name; strong: true }
        Lbl {
          p: root.p
          Layout.fillWidth: true
          dim: true
          elide: Text.ElideRight
          font.pixelSize: Style.font.caption
          text: px.modelData.type.toUpperCase() + " " + px.modelData.host + ":" + px.modelData.port
                + (px.st ? (px.st.ok ? " · " + px.st.ms + " ms" : " · down") : " · checking…")
        }
        LinkButton {
          p: root.p
          text: px.ck && px.ck.pending ? "Checking…" : "Check"
          onClicked: root.s.checkProxy(px.modelData.id)
        }
      }
      Lbl {
        p: root.p
        width: parent.width
        visible: !!px.st && !px.st.ok
        color: root.p.urgent
        wrapMode: Text.WordWrap
        maximumLineCount: 3
        font.pixelSize: Style.font.caption
        text: px.st && px.st.error ? px.st.error : ""
      }
      Lbl {
        p: root.p
        width: parent.width
        visible: !!px.ck && !px.ck.pending
        dim: true
        font.pixelSize: Style.font.caption
        text: !px.ck ? "" : px.ck.ok ? "Check passed: a test connection went through in " + px.ck.ms + " ms"
                                     : "Check failed: " + (px.ck.error || "")
      }

      // numbers
      Lbl {
        p: root.p
        width: parent.width
        font.pixelSize: Style.font.bodySmall
        text: px.live.length + " live now · " + root.s.proxyCarried5m(px.modelData.id) + " carried in the last 5 min"
      }

      // which policies route through it
      Lbl { p: root.p; dim: true; strong: true; text: "ROUTED BY"; font.pixelSize: Style.font.caption; font.letterSpacing: 1 }
      Lbl {
        p: root.p
        visible: px.routedBy.length === 0
        dim: true
        font.pixelSize: Style.font.caption
        text: root.s.defaultRoute === px.modelData.id ? "Everything else (the default route)"
              : "No policy yet. In Policies, choose Allow via proxy."
      }
      Repeater {
        model: px.routedBy
        delegate: RowLayout {
          required property var modelData
          width: px.width
          spacing: Style.space(8)
          Lbl {
            p: root.p
            Layout.fillWidth: true
            elide: Text.ElideMiddle
            text: (modelData.app === "*" ? "Any app" : modelData.app.split("/").pop())
                  + (modelData.via && modelData.via !== "*" ? " via " + Model.viaLabel(modelData.via) : "")
                  + "  →  " + (modelData.host === "*" ? "every host" : modelData.host)
                  + (modelData.port !== "*" ? ":" + modelData.port : "")
          }
          LinkButton { p: root.p; text: "Edit"; onClicked: root.p.openPolicy(modelData.id) }
        }
      }

      // live connections through it
      Lbl { p: root.p; dim: true; strong: true; text: "LIVE"; font.pixelSize: Style.font.caption; font.letterSpacing: 1 }
      Lbl {
        p: root.p
        visible: px.live.length === 0
        dim: true
        wrapMode: Text.WordWrap
        maximumLineCount: 2
        font.pixelSize: Style.font.caption
        text: "Nothing is going through " + px.modelData.name + " right now."
      }
      Repeater {
        model: px.live.slice(0, 40)
        delegate: ConnRow {
          required property var modelData
          width: px.width
          p: root.p; s: root.s; view: root.view
          conn: modelData
          showApp: true
          indent: 0
        }
      }

      // failures
      Lbl {
        p: root.p
        visible: px.failures.length > 0
        dim: true; strong: true
        text: "RECENT FAILURES (BLOCKED, NOT SENT DIRECT)"
        font.pixelSize: Style.font.caption
        font.letterSpacing: 1
      }
      Repeater {
        model: px.failures
        delegate: Lbl {
          required property var modelData
          p: root.p
          width: px.width
          color: root.p.urgent
          elide: Text.ElideRight
          font.pixelSize: Style.font.caption
          text: Model.clock(modelData.ts) + "  " + modelData.dst + ":" + modelData.port + "  " + modelData.error
        }
      }

      PanelSeparator { foreground: root.p.foreground }
    }
  }

  // everything no policy routes
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl {
      p: root.p
      Layout.fillWidth: true
      dim: true
      wrapMode: Text.WordWrap
      maximumLineCount: 2
      font.pixelSize: Style.font.caption
      text: "Everything else goes " + (root.s.defaultRoute === "direct" ? "direct" : "via " + root.s.proxyName(root.s.defaultRoute)) + "."
    }
    LinkButton { p: root.p; text: "Change"; onClicked: root.p.view = "settings" }
  }
}
