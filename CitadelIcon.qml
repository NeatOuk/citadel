import QtQuick
import qs.Commons
import qs.Ui

// Citadel's mark: a keep with three battlements and a gate arch, drawn on a
// Canvas so it needs no icon font. The gate shows the mode:
//   guarded  - solid door
//   open     - empty arch (gate raised)
//   lockdown - portcullis bars across the arch
// A corner badge counts connections waiting at the gate.
Item {
  id: root

  property real iconSize: Style.font.icon
  property color color: Color.foreground
  property color badgeColor: Color.urgent
  property string mode: "guarded"
  property int pendingCount: 0

  width: iconSize
  height: iconSize
  implicitWidth: iconSize
  implicitHeight: iconSize

  onColorChanged: tower.requestPaint()
  onModeChanged: tower.requestPaint()
  onIconSizeChanged: tower.requestPaint()

  Canvas {
    id: tower
    anchors.fill: parent
    Component.onCompleted: requestPaint()

    onPaint: {
      var ctx = getContext("2d")
      ctx.reset()
      var w = width, h = height
      var c = Qt.rgba(root.color.r, root.color.g, root.color.b, root.color.a)
      var sw = Math.max(1.2, w * 0.10)

      // keep outline with three merlons along the top
      var L = w * 0.16, R = w * 0.84, T = h * 0.10, B = h * 0.92
      var crenelDepth = h * 0.16
      var mw = (R - L) / 5
      ctx.beginPath()
      ctx.moveTo(L, B)
      ctx.lineTo(L, T)
      ctx.lineTo(L + mw, T)
      ctx.lineTo(L + mw, T + crenelDepth)
      ctx.lineTo(L + 2 * mw, T + crenelDepth)
      ctx.lineTo(L + 2 * mw, T)
      ctx.lineTo(L + 3 * mw, T)
      ctx.lineTo(L + 3 * mw, T + crenelDepth)
      ctx.lineTo(L + 4 * mw, T + crenelDepth)
      ctx.lineTo(L + 4 * mw, T)
      ctx.lineTo(R, T)
      ctx.lineTo(R, B)
      ctx.closePath()
      ctx.lineWidth = sw
      ctx.lineJoin = "miter"
      ctx.strokeStyle = c
      ctx.stroke()

      // gate arch
      var gw = w * 0.30, gx = w * 0.5 - gw / 2, gTop = h * 0.52
      ctx.beginPath()
      ctx.moveTo(gx, B)
      ctx.lineTo(gx, gTop + gw / 2)
      ctx.arc(w * 0.5, gTop + gw / 2, gw / 2, Math.PI, 0, false)
      ctx.lineTo(gx + gw, B)
      if (root.mode === "guarded") {
        ctx.closePath()
        ctx.fillStyle = c
        ctx.fill()
      } else {
        ctx.lineWidth = Math.max(1, sw * 0.8)
        ctx.stroke()
      }
      if (root.mode === "lockdown") {
        // portcullis: vertical bars + one cross bar
        ctx.lineWidth = Math.max(1, sw * 0.6)
        for (var i = 1; i <= 2; i++) {
          var x = gx + gw * i / 3
          ctx.beginPath(); ctx.moveTo(x, gTop + gw * 0.12); ctx.lineTo(x, B); ctx.stroke()
        }
        ctx.beginPath(); ctx.moveTo(gx, gTop + gw * 0.85); ctx.lineTo(gx + gw, gTop + gw * 0.85); ctx.stroke()
      }
    }
  }

  BorderSurface {
    visible: root.pendingCount > 0
    anchors.right: parent.right
    anchors.top: parent.top
    width: Math.max(7, parent.width * 0.40)
    height: width
    radius: width / 2
    color: root.badgeColor
    borderSpec: Border.flat(Color.popups.background, 1)
  }
}
