import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// Import policies from other tools: AdGuard / AdGuard Home rules, Pi-hole
// lists, hosts files, plain domain lists or a Citadel export, pasted or
// fetched from a URL (a GitHub page link is turned into its raw file).
// Big block lists become a feed; see Service.importText.
Column {
  id: root
  property var p: null
  property var s: null
  property string plainAs: "deny"           // what a bare "example.com" line means
  property string message: ""
  property bool busy: false
  signal pasteRequested()                   // the view reads the clipboard and calls importPasted()

  spacing: Style.space(6)

  function importPasted(text) {
    if (!String(text || "").trim()) { message = "The clipboard is empty."; return }
    message = s.importText(text, { plainAs: plainAs, name: "clipboard" })
  }

  // https://github.com/u/r/blob/main/list.txt -> raw.githubusercontent.com/u/r/main/list.txt
  function rawUrl(u) {
    var m = /^https:\/\/github\.com\/([^\/]+)\/([^\/]+)\/blob\/(.+)$/.exec(u)
    return m ? "https://raw.githubusercontent.com/" + m[1] + "/" + m[2] + "/" + m[3] : u
  }
  function fetch() {
    var url = rawUrl(urlField.text.trim())
    if (!/^https?:\/\//.test(url)) { message = "Enter an http(s) URL."; return }
    busy = true
    message = "Fetching…"
    var x = new XMLHttpRequest()
    x.onreadystatechange = function() {
      if (x.readyState !== XMLHttpRequest.DONE) return
      root.busy = false
      fetchTimeout.stop()
      if (x.status !== 200) { root.message = "Fetch failed" + (x.status ? ": HTTP " + x.status : "") + "."; return }
      var name = url.replace(/[?#].*$/, "").split("/").filter(function(p) { return p }).pop() || url
      root.message = root.s.importText(x.responseText, { plainAs: root.plainAs, url: url, name: name })
      urlField.text = ""
    }
    x.open("GET", url)
    x.send()
    fetchTimeout.xhr = x
    fetchTimeout.restart()
  }
  Timer {
    id: fetchTimeout
    property var xhr: null
    interval: 60000
    onTriggered: if (xhr && root.busy) { xhr.abort(); root.busy = false; root.message = "Fetch timed out." }
  }

  Lbl {
    p: root.p
    width: parent.width
    dim: true
    wrapMode: Text.WordWrap
    maximumLineCount: 4
    font.pixelSize: Style.font.caption
    text: "AdGuard rules, a Pi-hole list, a hosts file or a Citadel export. Up to "
          + root.s.importFeedThreshold + " blocked domains become policies; bigger lists become a feed. "
          + "Regex rules and AdGuard options Citadel can't apply are skipped."
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(6)
    TextField {
      id: urlField
      Layout.fillWidth: true
      placeholderText: "https://… list URL (GitHub links work)"
      foreground: root.p.foreground
      onAccepted: if (!root.busy) root.fetch()
    }
    Button {
      text: root.busy ? "Fetching…" : "Fetch"
      enabled: !root.busy
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: root.fetch()
    }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl { p: root.p; dim: true; text: "Plain domains are"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      options: [{ value: "deny", label: "Block" }, { value: "allow", label: "Allow" }]
      value: root.plainAs
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.plainAs = v }
    }
    Item { Layout.fillWidth: true }
    Button {
      text: "Paste from clipboard"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: root.pasteRequested()
    }
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: root.message !== ""
    wrapMode: Text.WordWrap
    maximumLineCount: 4
    font.pixelSize: Style.font.caption
    text: root.message
  }
}
