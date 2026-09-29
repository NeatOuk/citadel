import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// One live connection: destination, protocol, bytes, verdict, route, and
// Allow / Block. Used by Traffic's Apps and Proxy tabs.
RowLayout {
  id: row
  property var p: null
  property var s: null
  property var view: null           // TrafficView, for statusColor / statusText
  property var conn: ({})
  property bool showApp: false      // prefix the app (the Proxy tab lists several apps)
  property bool showCmd: false
  property real indent: Style.space(9)
  readonly property var d: s ? s.decisions[conn.key] : null

  spacing: Style.space(6)
  Item { width: row.indent }
  Rectangle {
    width: Style.space(5); height: width; radius: width / 2
    color: row.view ? row.view.statusColor(row.d) : row.p.foreground
  }
  Column {
    Layout.fillWidth: true
    spacing: 0
    Lbl {
      p: row.p
      width: parent.width
      text: (row.showApp ? Model.appWithOrigin(row.conn) + "  →  " : "")
            + (row.conn.cc ? Model.flag(row.conn.cc) + " " : "") + Model.destLabel(row.conn) + ":" + row.conn.rport
      elide: Text.ElideMiddle
    }
    Lbl {
      p: row.p
      width: parent.width
      dim: true
      font.pixelSize: Style.font.caption
      elide: Text.ElideRight
      text: String(row.conn.proto || "").toUpperCase()
            + (row.conn.state === "syn-sent" ? " · connecting" : "")
            + (row.conn.host ? " · " + row.conn.raddr : "")
            + " · ↓" + Model.humanBytes(row.conn.down) + " ↑" + Model.humanBytes(row.conn.up)
            + (row.view ? " · " + row.view.statusText(row.d) : "")
            + (function(r) { return r ? " · via " + r.name : "" })(row.s ? row.s.routeOf(row.conn) : null)
    }
    Lbl {
      p: row.p
      width: parent.width
      visible: row.showCmd && !!row.conn.cmd
      dim: true
      font.pixelSize: Style.font.caption
      elide: Text.ElideMiddle
      text: "$ " + (row.conn.cmd || "")
    }
  }
  LinkButton {
    p: row.p
    visible: !row.conn.system
    text: "Allow"
    onClicked: row.s.allowConn(row.conn)
  }
  LinkButton {
    p: row.p
    danger: true
    visible: !row.conn.system
    text: "Block"
    onClicked: row.s.denyConn(row.conn)
  }
}
