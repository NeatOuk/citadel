import QtQuick
import qs.Commons

// Plain text with the panel's defaults, so views stay short.
Text {
  property var p: null
  property bool dim: false
  property bool strong: false
  textFormat: Text.PlainText
  color: p ? (dim ? p.dim : p.foreground) : Color.foreground
  font.family: p ? p.fontFamily : Style.font.family
  font.pixelSize: Style.font.bodySmall
  font.bold: strong
  elide: Text.ElideRight
  maximumLineCount: 1
}
