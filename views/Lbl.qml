import QtQuick
import qs.Commons
import qs.Commons as C   // Qt 6.12's QtQuick has its own Color type, which hides ours

// Plain text with the panel's defaults, so views stay short.
Text {
  property var p: null
  property bool dim: false
  property bool strong: false
  textFormat: Text.PlainText
  color: p ? (dim ? p.dim : p.foreground) : C.Color.foreground
  font.family: p ? p.fontFamily : Style.font.family
  font.pixelSize: Style.font.bodySmall
  font.bold: strong
  elide: Text.ElideRight
  maximumLineCount: 1
}
