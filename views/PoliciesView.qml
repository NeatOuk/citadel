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
  property string listQuery: ""
  property string listShow: "all"            // all | you | gate | deny | proxy
  property string listSort: "newest"         // newest | precedence
  property string highlightId: ""            // the policy just saved
  property string editId: ""
  property string formApp: "*"
  property string formVia: "*"
  property string formAction: "deny"           // deny | allow | proxy (allow via a proxy)
  property string formProfile: "*"
  property string formDuration: "forever"
  property string formRoute: "default"
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
  // launchers seen in traffic (and in existing policies) for "Started by"
  readonly property var viaChoices: {
    var seen = { "*": true }
    var out = [{ value: "*", label: "However it starts" }]
    function add(id, name, kind) {
      if (!id || seen[id]) return
      seen[id] = true
      out.push({ value: id, label: (kind === "terminal" ? "in " : "via ") + (name || Model.viaLabel(id)) + (id.indexOf("/") === 0 ? "  —  " + id : "") })
    }
    s.conns.forEach(function(c) { if (!c.system && (formApp === "*" || c.exe === formApp)) add(c.viaId, c.via, c.viaKind) })
    s.rules.forEach(function(r) { if (r.via && r.via !== "*") add(r.via, Model.viaLabel(r.via), "") })
    return out
  }
  // "Allow via proxy": which proxy. Direct is offered only when everything
  // else already goes through a proxy (otherwise plain Allow is direct).
  readonly property var routeChoices: s.proxies.map(function(x) { return { value: x.id, label: x.name + "  —  " + x.type.toUpperCase() + " " + x.host + ":" + x.port } })
    .concat(s.defaultRoute !== "direct" ? [{ value: "direct", label: "Direct (skip the proxy)" }] : [])
  readonly property var profileChoices: [{ value: "*", label: "All zones" }].concat(
    s.profiles.map(function(pr) { return { value: pr.name, label: pr.name + " zone" } }))
  readonly property var shownRules: Model.filterRules(s.rules,
    { query: listQuery, show: listShow, sort: listSort, profile: filterProfile }, s.proxyName)

  function describe(r) {
    var who = (r.app === "*" ? "Any app" : r.app.split("/").pop())
              + (r.via && r.via !== "*" ? " via " + Model.viaLabel(r.via) : "")
    var where = r.host === "*" ? "every host" : r.host
    return who + "  →  " + where + (r.port !== "*" ? ":" + r.port : "")
           + (r.action === "allow" && r.route && r.route !== "default"
              ? (r.route === "direct" ? "  · direct" : "  · via " + s.proxyName(r.route)) : "")
  }
  // Dropdowns overwrite their own `value` when used, which breaks a binding,
  // so the form pushes values into them explicitly.
  function _syncForm() {
    appDrop.value = formApp; viaDrop.value = formVia; zoneDrop.value = formProfile
    if (formAction === "proxy") routeDrop.value = formRoute
  }
  function resetForm() {
    editId = ""; formApp = "*"; formVia = "*"; formAction = "deny"; formProfile = "*"; formDuration = "forever"; formRoute = "default"
    hostField.text = ""; portField.text = ""
    _syncForm()
  }
  function edit(r) {
    editId = r.id; formApp = r.app; formVia = r.via || "*"; formProfile = r.profile
    var routed = r.action === "allow" && r.route && r.route !== "default"
                 && !(r.route === "direct" && s.defaultRoute === "direct")
    formAction = routed ? "proxy" : r.action
    formRoute = routed ? r.route : "default"
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
    if (formAction === "proxy" && (formRoute === "default" || !routeChoices.some(function(c) { return c.value === formRoute }))) {
      message = s.proxies.length ? "Pick a proxy." : "Add a proxy in Settings first."; return
    }
    var fields = { app: formApp, via: formApp === "*" ? "*" : formVia, host: host, port: port,
                   action: formAction === "deny" ? "deny" : "allow", profile: formProfile,
                   route: formAction === "proxy" ? formRoute : "default",
                   duration: formDuration,
                   pids: formDuration === "untilQuit" && s.apps[formApp] ? s.apps[formApp].pids : [] }
    var savedId = editId
    if (editId) s.updateRule(editId, fields); else savedId = s.addRule(fields).id
    var done = editId ? "Policy updated." : "Policy added."
    // show it where it can be found: at the top of "Added by you"
    listQuery = ""; searchField.text = ""
    if (listShow !== "all" && listShow !== "you") listShow = "you"
    listSort = "newest"
    highlightId = savedId
    highlightTimer.restart()
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
    onChanged: function(v) { root.formApp = v; root.formVia = "*" }
  }
  Dropdown {
    id: viaDrop
    width: parent.width
    visible: root.formApp !== "*" && root.viaChoices.length > 1
    label: "Started by"
    value: root.formVia
    options: root.viaChoices
    foreground: root.p.foreground
    onChanged: function(v) { root.formVia = v }
  }
  // styled like the Dropdown labels above it
  Text {
    text: "Destination (where the app connects)"
    textFormat: Text.PlainText
    color: Qt.darker(root.p.foreground, 1.4)
    font.family: root.p.fontFamily
    font.pixelSize: Style.font.caption
    font.bold: true
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(6)
    TextField {
      id: hostField
      Layout.fillWidth: true
      placeholderText: "host, domain, IP or CIDR (empty = anywhere)"
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
      options: [{ value: "deny", label: "Block" }, { value: "allow", label: "Allow" },
                { value: "proxy", label: "Allow via proxy" }]
      value: root.formAction
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) {
        root.formAction = v
        if (v === "proxy" && root.formRoute === "default" && root.routeChoices.length) {
          root.formRoute = root.routeChoices[0].value
          routeDrop.value = root.formRoute
        }
      }
    }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(10)
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
    id: routeDrop
    width: parent.width
    visible: root.formAction === "proxy" && root.s.proxies.length > 0
    label: "Proxy"
    value: root.formRoute
    options: root.routeChoices
    foreground: root.p.foreground
    onChanged: function(v) { root.formRoute = v }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    visible: root.formAction === "proxy" && root.s.proxies.length === 0
    Lbl {
      p: root.p
      Layout.fillWidth: true
      dim: true
      wrapMode: Text.WordWrap
      maximumLineCount: 2
      font.pixelSize: Style.font.caption
      text: "No proxies yet. Add one in Settings, then pick it here."
    }
    LinkButton { p: root.p; text: "Add a proxy"; onClicked: root.p.view = "settings" }
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: routeDrop.visible && root.formRoute !== "direct"
             && root.formApp === "*" && hostField.text.trim() !== ""
    wrapMode: Text.WordWrap
    maximumLineCount: 3
    dim: true
    font.pixelSize: Style.font.caption
    text: "A host-only proxy route covers the addresses Citadel has resolved or seen for that host; the first connection to a brand-new address may use the default route. Pick an app for an exact route."
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
  Timer { id: highlightTimer; interval: 8000; onTriggered: root.highlightId = "" }
  TextField {
    id: searchField
    width: parent.width
    placeholderText: "search app, host, IP or proxy"
    foreground: root.p.foreground
    onTextChanged: root.listQuery = text
  }
  ButtonGroup {
    options: [{ value: "all", label: "All" }, { value: "you", label: "Added by you" }, { value: "gate", label: "From the gate" },
              { value: "deny", label: "Blocks" }, { value: "proxy", label: "Via proxy" }]
    value: root.listShow
    foreground: root.p.foreground
    fontFamily: root.p.fontFamily
    fontSize: Style.font.caption
    onChanged: function(v) { root.listShow = v }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    ButtonGroup {
      visible: root.s.profiles.length > 1
      options: [{ value: "*all*", label: "All zones" }].concat(root.s.profiles.map(function(pr) { return { value: pr.name, label: pr.name } }))
      value: root.filterProfile
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.filterProfile = v }
    }
    ButtonGroup {
      options: [{ value: "newest", label: "Newest" }, { value: "precedence", label: "Precedence" }]
      value: root.listSort
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.listSort = v }
    }
    Lbl {
      p: root.p
      Layout.fillWidth: true
      horizontalAlignment: Text.AlignRight
      dim: true
      font.pixelSize: Style.font.caption
      text: root.shownRules.length + " of " + root.s.rules.length
    }
  }
  Lbl {
    p: root.p
    visible: root.shownRules.length === 0
    dim: true
    width: parent.width
    wrapMode: Text.WordWrap
    maximumLineCount: 3
    text: root.s.rules.length === 0
          ? "No policies yet. Choose “Always allow” or “Block” at the gate, use Allow / Block in Traffic, or add one above."
          : "No policy matches."
  }
  Repeater {
    model: root.shownRules
    delegate: Item {
      id: ruleItem
      required property var modelData
      width: root.width
      height: ruleRow.implicitHeight
      // the policy just saved stands out for a few seconds
      Rectangle {
        anchors.fill: parent
        anchors.margins: -Style.space(3)
        radius: Style.cornerRadius
        visible: root.highlightId === ruleItem.modelData.id
        color: Qt.rgba(root.p.foreground.r, root.p.foreground.g, root.p.foreground.b, 0.10)
      }
      RowLayout {
      id: ruleRow
      readonly property var modelData: ruleItem.modelData
      width: parent.width
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
          text: (modelData.origin === "gate" ? "from the gate " : "added by you ") + Model.ago(modelData.createdAt, root.s.now)
                + " · " + (modelData.profile === "*" ? "all zones" : modelData.profile + " zone")
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
