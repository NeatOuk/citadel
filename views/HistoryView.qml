import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// History: last-hour chart, top apps / hosts / countries (from the monitor's
// sqlite history) and the log of verdicts.
Column {
  id: root
  property var p: null
  property var s: null
  property string range: "today"

  spacing: Style.space(8)

  readonly property var series: s.stats.series || []
  readonly property var hourTotals: {
    var up = 0, down = 0
    for (var i = 0; i < series.length; i++) { up += series[i].up || 0; down += series[i].down || 0 }
    return { up: up, down: down }
  }

  // ---------------------------------------------------------------- chart
  RowLayout {
    width: parent.width
    PanelSectionHeader { text: "LAST HOUR"; foreground: root.p.foreground; fontFamily: root.p.fontFamily; Layout.fillWidth: true }
    Lbl { p: root.p; text: "↓ " + Model.humanBytes(root.hourTotals.down); color: Color.accent; font.pixelSize: Style.font.caption }
    Lbl { p: root.p; text: "↑ " + Model.humanBytes(root.hourTotals.up); color: root.p.urgent; font.pixelSize: Style.font.caption }
  }
  Sparkline {
    id: spark
    width: parent.width
    height: Style.space(70)
    series: root.series
    downColor: Color.accent
    upColor: root.p.urgent
    gridColor: Qt.rgba(root.p.foreground.r, root.p.foreground.g, root.p.foreground.b, 0.08)
  }
  RowLayout {
    width: parent.width
    Lbl { p: root.p; dim: true; text: "60 min ago"; font.pixelSize: Style.font.caption; Layout.fillWidth: true }
    Lbl { p: root.p; dim: true; text: "peak " + Model.humanBytes(spark.peak) + "/min"; font.pixelSize: Style.font.caption }
    Item { Layout.fillWidth: true }
    Lbl { p: root.p; dim: true; text: "now"; font.pixelSize: Style.font.caption }
  }

  // ---------------------------------------------------------------- tops
  PanelSeparator { foreground: root.p.foreground }
  ButtonGroup {
    options: [{ value: "today", label: "Today" }, { value: "week", label: "7 days" }]
    value: root.range
    foreground: root.p.foreground
    fontFamily: root.p.fontFamily
    fontSize: Style.font.caption
    onChanged: function(v) { root.range = v }
  }

  component BarList: Column {
    id: bl
    property string title: ""
    property var items: []
    property bool countries: false
    readonly property real maxBytes: {
      var m = 1
      for (var i = 0; i < items.length; i++) m = Math.max(m, (items[i].up || 0) + (items[i].down || 0))
      return m
    }
    width: root.width
    spacing: Style.space(3)
    PanelSectionHeader { text: bl.title; foreground: root.p.foreground; fontFamily: root.p.fontFamily }
    Lbl { p: root.p; visible: bl.items.length === 0; dim: true; text: "Nothing recorded yet."; font.pixelSize: Style.font.caption }
    Repeater {
      model: bl.items
      delegate: Item {
        required property var modelData
        width: bl.width
        height: Style.space(20)
        Rectangle {
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          height: parent.height - Style.space(4)
          width: parent.width * ((modelData.up || 0) + (modelData.down || 0)) / bl.maxBytes
          color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.16)
        }
        Lbl {
          p: root.p
          anchors.left: parent.left
          anchors.leftMargin: Style.space(4)
          anchors.right: amount.left
          anchors.verticalCenter: parent.verticalCenter
          text: bl.countries ? (Model.flag(modelData.name) + "  " + modelData.name) : modelData.name
          elide: Text.ElideMiddle
        }
        Lbl {
          id: amount
          p: root.p
          anchors.right: parent.right
          anchors.rightMargin: Style.space(4)
          anchors.verticalCenter: parent.verticalCenter
          dim: true
          font.pixelSize: Style.font.caption
          text: "↓" + Model.humanBytes(modelData.down) + "  ↑" + Model.humanBytes(modelData.up)
                + "  · " + modelData.flows + " conn"
        }
      }
    }
  }

  BarList {
    title: root.range === "today" ? "TOP APPS TODAY" : "TOP APPS · 7 DAYS"
    items: root.range === "today" ? (root.s.stats.topAppsToday || []) : (root.s.stats.topApps7d || [])
  }
  BarList {
    visible: root.range === "today"
    title: "TOP HOSTS TODAY"
    items: root.s.stats.topHostsToday || []
  }
  BarList {
    visible: root.range === "today"
    title: "COUNTRIES TODAY"
    countries: true
    items: root.s.stats.countriesToday || []
  }
  RowLayout {
    width: parent.width
    visible: !root.s.geoip.installed
    Lbl {
      p: root.p
      Layout.fillWidth: true
      dim: true
      wrapMode: Text.WordWrap
      maximumLineCount: 2
      font.pixelSize: Style.font.caption
      text: root.s.geoip.error ? "GeoIP: " + root.s.geoip.error
          : "Countries need the free DB-IP country database (about 8 MB)."
    }
    Button {
      text: root.s.geoip.downloading ? "Downloading…" : "Download"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: root.s.downloadGeoip()
    }
  }

  // ---------------------------------------------------------------- log
  PanelSeparator { foreground: root.p.foreground }
  RowLayout {
    width: parent.width
    PanelSectionHeader { text: "VERDICTS"; foreground: root.p.foreground; fontFamily: root.p.fontFamily; Layout.fillWidth: true }
    LinkButton { p: root.p; text: "Clear"; visible: root.s.decisionLog.length > 0; onClicked: root.s.clearLog() }
  }
  Lbl {
    p: root.p
    visible: root.s.decisionLog.length === 0
    dim: true
    text: "Your verdicts at the gate, plus what Open, Lockdown and threat feeds decided, appear here."
    font.pixelSize: Style.font.caption
  }
  Repeater {
    model: root.s.decisionLog.slice(0, 40)
    delegate: RowLayout {
      required property var modelData
      width: root.width
      spacing: Style.space(6)
      Lbl { p: root.p; dim: true; text: Model.clock(modelData.ts); font.pixelSize: Style.font.caption }
      Lbl {
        p: root.p
        text: modelData.verdict === "deny" ? "✕" : "✓"
        color: modelData.verdict === "deny" ? root.p.urgent : root.p.foreground
        font.pixelSize: Style.font.caption
        strong: true
      }
      Lbl {
        p: root.p
        Layout.fillWidth: true
        text: modelData.app + " → " + (modelData.cc ? Model.flag(modelData.cc) + " " : "") + modelData.dest + ":" + modelData.port
        font.pixelSize: Style.font.caption
        elide: Text.ElideMiddle
      }
      Lbl { p: root.p; dim: true; text: modelData.source; font.pixelSize: Style.font.caption }
    }
  }
}
