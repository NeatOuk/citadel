import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// Policies (filterable by zone), the add/edit form, import/export through
// the clipboard, and threat feed subscriptions.
Column {
  id: root
  property var p: null
  property var s: null
  property string filterProfile: "*all*"
  property string editId: ""
  property string formApp: "*"
  property string formAction: "deny"
  property string formProfile: "*"
  property string formDuration: "forever"
  property string message: ""

  spacing: Style.space(8)

  readonly property var appChoices: {
    var seen = { "*": true }
    var out = [{ value: "*", label: "Any app" }]
    var exes = Object.keys(s.apps).sort(function(a, b) { return s.apps[a].name.localeCompare(s.apps[b].name) })
    s.rules.forEach(function(r) { if (r.app !== "*" && exes.indexOf(r.app) === -1) exes.push(r.app) })
    exes.forEach(function(e) {
      if (seen[e]) return
      seen[e] = true
      out.push({ value: e, label: e.split("/").pop() + "  —  " + e })
    })
    return out
  }
  readonly property var profileChoices: [{ value: "*", label: "All zones" }].concat(
    s.profiles.map(function(pr) { return { value: pr.name, label: pr.name + " zone" } }))
  readonly property var shownRules: s.rules.filter(function(r) {
    return filterProfile === "*all*" || r.profile === filterProfile || r.profile === "*"
  }).slice().sort(function(a, b) { return Model.specificity(b) - Model.specificity(a) || b.createdAt - a.createdAt })

  function describe(r) {
    var who = r.app === "*" ? "Any app" : r.app.split("/").pop()
    var where = r.host === "*" ? "every host" : r.host
    return who + "  →  " + where + (r.port !== "*" ? ":" + r.port : "")
  }
  // Dropdowns overwrite their own `value` when used, which breaks a binding,
  // so the form pushes values into them explicitly.
  function _syncForm() {
    appDrop.value = formApp; zoneDrop.value = formProfile
  }
  function resetForm() {
    editId = ""; formApp = "*"; formAction = "deny"; formProfile = "*"; formDuration = "forever"
    hostField.text = ""; portField.text = ""
    _syncForm()
  }
  function edit(r) {
    editId = r.id; formApp = r.app; formAction = r.action; formProfile = r.profile
    formDuration = r.duration === "untilQuit" ? "untilQuit" : "forever"
    hostField.text = r.host === "*" ? "" : r.host
    portField.text = r.port === "*" ? "" : String(r.port)
    _syncForm()
    message = "Editing: " + describe(r)
    if (p && p.scrollToTop) p.scrollToTop()        // the form sits above the list
  }
  function submit() {
    var host = hostField.text.trim() || "*"
    var port = portField.text.trim() || "*"
    if (formApp === "*" && host === "*") { message = "Choose an app, a host, or both."; return }
    if (port !== "*" && !(Number(port) >= 1 && Number(port) <= 65535)) { message = "Port must be 1–65535."; return }
    var fields = { app: formApp, host: host, port: port, action: formAction, profile: formProfile,
                   duration: formDuration,
                   pids: formDuration === "untilQuit" && s.apps[formApp] ? s.apps[formApp].pids : [] }
    if (editId) s.updateRule(editId, fields); else s.addRule(fields)
    var done = editId ? "Policy updated." : "Policy added."
    resetForm()
    message = done
  }

  // ---------------------------------------------------------------- clipboard
  Process {
    id: copyProc
    stdinEnabled: true
    property string payload: ""
    command: ["wl-copy"]
    onStarted: { write(payload); stdinEnabled = false }
    onExited: { stdinEnabled = true; root.message = "Policies copied to the clipboard." }
  }
  Process {
    id: pasteProc
    command: ["wl-paste", "--no-newline"]
    stdout: StdioCollector { id: pasteOut; waitForEnd: true }
    onExited: {
      var err = root.s.importRules(String(pasteOut.text || ""))
      root.message = err ? "Import failed: " + err : "Policies imported from the clipboard."
    }
  }

  // ---------------------------------------------------------------- list
  RowLayout {
    width: parent.width
    PanelSectionHeader { text: "POLICIES"; foreground: root.p.foreground; fontFamily: root.p.fontFamily; Layout.fillWidth: true }
    LinkButton { p: root.p; text: "Export"; onClicked: { copyProc.payload = root.s.exportRules(); copyProc.running = true } }
    LinkButton { p: root.p; text: "Import"; onClicked: pasteProc.running = true }
  }
  // ---------------------------------------------------------------- form
  PanelSectionHeader { text: root.editId ? "EDIT POLICY" : "NEW POLICY"; foreground: root.p.foreground; fontFamily: root.p.fontFamily }
  Dropdown {
    id: appDrop
    width: parent.width
    label: "App"
    value: root.formApp
    options: root.appChoices
    foreground: root.p.foreground
    onChanged: function(v) { root.formApp = v }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(6)
    TextField {
      id: hostField
      Layout.fillWidth: true
      placeholderText: "host, domain, IP or CIDR (empty = any)"
      foreground: root.p.foreground
      onAccepted: root.submit()
    }
    TextField {
      id: portField
      Layout.preferredWidth: Style.space(70)
      placeholderText: "port"
      foreground: root.p.foreground
      onAccepted: root.submit()
    }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(10)
    ButtonGroup {
      options: [{ value: "deny", label: "Block" }, { value: "allow", label: "Allow" }]
      value: root.formAction
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.formAction = v }
    }
    ButtonGroup {
      options: [{ value: "forever", label: "From now on" }, { value: "untilQuit", label: "Until the app quits" }]
      value: root.formDuration
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.formDuration = v }
    }
  }
  Dropdown {
    id: zoneDrop
    width: parent.width
    label: "Zone"
    value: root.formProfile
    options: root.profileChoices
    foreground: root.p.foreground
    onChanged: function(v) { root.formProfile = v }
  }
  RowLayout {
    width: parent.width
    Lbl { p: root.p; Layout.fillWidth: true; dim: true; text: root.message; font.pixelSize: Style.font.caption }
    Button {
      visible: root.editId !== ""
      text: "Cancel"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      onClicked: root.resetForm()
    }
    Button {
      text: root.editId ? "Save policy" : "Add policy"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: root.submit()
    }
  }

  PanelSeparator { foreground: root.p.foreground }
  ButtonGroup {
    options: [{ value: "*all*", label: "All zones" }].concat(root.s.profiles.map(function(pr) { return { value: pr.name, label: pr.name } }))
    value: root.filterProfile
    foreground: root.p.foreground
    fontFamily: root.p.fontFamily
    fontSize: Style.font.caption
    onChanged: function(v) { root.filterProfile = v }
  }
  Lbl {
    p: root.p
    visible: root.shownRules.length === 0
    dim: true
    width: parent.width
    wrapMode: Text.WordWrap
    maximumLineCount: 3
    text: "No policies yet. Choose “Always allow” or “Block” at the gate, use Allow / Block in Traffic, or add one below."
  }
  Repeater {
    model: root.shownRules
    delegate: RowLayout {
      required property var modelData
      width: root.width
      spacing: Style.space(8)
      Lbl {
        p: root.p
        text: modelData.action === "deny" ? "✕" : "✓"
        color: modelData.action === "deny" ? root.p.urgent : root.p.foreground
        strong: true
        font.pixelSize: Style.font.body
      }
      Column {
        Layout.fillWidth: true
        Lbl { p: root.p; width: parent.width; text: root.describe(modelData); elide: Text.ElideMiddle }
        Lbl {
          p: root.p
          width: parent.width
          dim: true
          font.pixelSize: Style.font.caption
          text: (modelData.profile === "*" ? "all zones" : modelData.profile + " zone")
                + (modelData.duration === "untilQuit" ? " · until the app quits" : "")
                + (root.s.approx[modelData.id] ? " · per destination (app shares its group)" : "")
                + (modelData.note ? " · " + modelData.note : "")
        }
      }
      LinkButton {
        p: root.p
        text: root.editId === modelData.id ? "Editing" : "Edit"
        font.underline: root.editId === modelData.id
        onClicked: root.editId === modelData.id ? root.resetForm() : root.edit(modelData)
      }
      LinkButton { p: root.p; danger: true; text: "Remove"; onClicked: root.s.removeRule(modelData.id) }
    }
  }

  // ---------------------------------------------------------------- blocklists
  PanelSeparator { foreground: root.p.foreground }
  RowLayout {
    width: parent.width
    PanelSectionHeader { text: "THREAT FEEDS"; foreground: root.p.foreground; fontFamily: root.p.fontFamily; Layout.fillWidth: true }
    LinkButton { p: root.p; text: "Update now"; onClicked: root.s.refreshLists() }
  }
  Lbl {
    p: root.p
    width: parent.width
    dim: true
    wrapMode: Text.WordWrap
    maximumLineCount: 3
    font.pixelSize: Style.font.caption
    text: "IP feeds go straight into the firewall; your LAN and local ranges are never blocked. Domain feeds block connections whose host name matches. Feeds refresh daily."
  }
  Repeater {
    model: root.s.lists
    delegate: RowLayout {
      required property var modelData
      readonly property var st: root.s.listStatus[modelData.id] || null
      width: root.width
      spacing: Style.space(8)
      ToggleSwitch {
        checked: !!modelData.enabled
        foreground: root.p.foreground
        onToggled: root.s.setListEnabled(modelData.id, !modelData.enabled)
      }
      Column {
        Layout.fillWidth: true
        Lbl { p: root.p; width: parent.width; text: modelData.name }
        Lbl {
          p: root.p
          width: parent.width
          dim: true
          font.pixelSize: Style.font.caption
          color: st && st.error ? root.p.urgent : root.p.dim
          text: (modelData.kind === "ip" ? "IP feed" : "domain feed")
                + (!modelData.enabled ? " · off"
                   : st ? " · " + st.count.toLocaleString() + " entries" + (st.updated ? " · " + Model.ago(st.updated, root.s.now) : "")
                          + (st.error ? " · " + st.error : "")
                   : " · loading…")
        }
      }
      LinkButton {
        p: root.p
        danger: true
        visible: String(modelData.id).indexOf("custom-") === 0
        text: "Remove"
        onClicked: root.s.removeList(modelData.id)
      }
    }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(6)
    TextField {
      id: listUrl
      Layout.fillWidth: true
      placeholderText: "https:// feed URL (hosts file, domains or CIDRs)"
      foreground: root.p.foreground
    }
    ButtonGroup {
      id: listKind
      options: [{ value: "domain", label: "Domains" }, { value: "ip", label: "IPs" }]
      value: "domain"
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { listKind.value = v }
    }
    Button {
      text: "Add"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: { root.s.addList("", listUrl.text, listKind.value); listUrl.text = "" }
    }
  }
}
