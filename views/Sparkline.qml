import QtQuick
import qs.Commons

// Two-series area chart (download filled, upload line) for per-minute bytes.
Item {
  id: root
  property var series: []          // [{t, up, down}]
  property color downColor: Color.accent
  property color upColor: Color.urgent
  property color gridColor: Qt.rgba(1, 1, 1, 0.08)
  readonly property real peak: {
    var m = 0
    for (var i = 0; i < series.length; i++) m = Math.max(m, series[i].up || 0, series[i].down || 0)
    return m
  }
  onSeriesChanged: canvas.requestPaint()
  onWidthChanged: canvas.requestPaint()

  Canvas {
    id: canvas
    anchors.fill: parent
    onPaint: {
      var ctx = getContext("2d")
      ctx.reset()
      var w = width, h = height, n = root.series.length
      ctx.strokeStyle = root.gridColor
      ctx.lineWidth = 1
      for (var g = 1; g < 4; g++) {
        ctx.beginPath(); ctx.moveTo(0, Math.round(h * g / 4) + 0.5); ctx.lineTo(w, Math.round(h * g / 4) + 0.5); ctx.stroke()
      }
      if (n < 2 || root.peak <= 0) return
      function x(i) { return i * w / (n - 1) }
      function y(v) { return h - 1 - (v / root.peak) * (h - 3) }
      // download: filled area
      ctx.beginPath()
      ctx.moveTo(0, h)
      for (var i = 0; i < n; i++) ctx.lineTo(x(i), y(root.series[i].down || 0))
      ctx.lineTo(w, h)
      ctx.closePath()
      ctx.fillStyle = Qt.rgba(root.downColor.r, root.downColor.g, root.downColor.b, 0.28)
      ctx.fill()
      ctx.beginPath()
      for (var j = 0; j < n; j++) {
        if (j === 0) ctx.moveTo(x(j), y(root.series[j].down || 0)); else ctx.lineTo(x(j), y(root.series[j].down || 0))
      }
      ctx.strokeStyle = root.downColor
      ctx.lineWidth = 1.5
      ctx.stroke()
      // upload: line
      ctx.beginPath()
      for (var k = 0; k < n; k++) {
        if (k === 0) ctx.moveTo(x(k), y(root.series[k].up || 0)); else ctx.lineTo(x(k), y(root.series[k].up || 0))
      }
      ctx.strokeStyle = root.upColor
      ctx.lineWidth = 1.5
      ctx.stroke()
    }
  }
}
