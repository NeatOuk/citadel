import QtQuick
import qs.Commons

// Compact text action for dense rows (Allow / Deny / Remove).
Text {
  id: link
  property var p: null
  property bool danger: false
  signal clicked()
  textFormat: Text.PlainText
  color: danger ? (p ? p.urgent : Color.urgent) : (p ? p.foreground : Color.foreground)
  opacity: area.containsMouse ? 1.0 : 0.72
  font.family: p ? p.fontFamily : Style.font.family
  font.pixelSize: Style.font.caption
  font.bold: true
  font.underline: area.containsMouse
  MouseArea {
    id: area
    anchors.fill: parent
    anchors.margins: -Style.space(3)
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    onClicked: link.clicked()
  }
}
