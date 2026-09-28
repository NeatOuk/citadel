import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// Enforcement, mode timer, zones, gate behaviour, data.
Column {
  id: root
  property var p: null
  property var s: null

  spacing: Style.space(8)

  // ---------------------------------------------------------------- environment
  Lbl {
    p: root.p
    width: parent.width
    visible: !root.s.omarchySupported
    color: root.p.urgent
    wrapMode: Text.WordWrap
    maximumLineCount: 3
    font.pixelSize: Style.font.caption
    text: "Citadel is built for Omarchy " + root.s.testedOmarchy + ".x and you are running " + root.s.omarchyVersion
          + ". If something looks off, check for a Citadel update."
  }

  // ---------------------------------------------------------------- firewall
  PanelSectionHeader { text: "ENFORCEMENT"; foreground: root.p.foreground; fontFamily: root.p.fontFamily }
  RowLayout {
    width: parent.width
    spacing: Style.space(10)
    Column {
      Layout.fillWidth: true
      spacing: Style.space(2)
      Lbl {
        p: root.p
        width: parent.width
        text: root.s.enforceBusy ? "Applying policies…"
            : root.s.enforce && root.s.enforceActive ? "Enforcing policies"
            : root.s.enforce ? "Raising the walls…" : "Watching only (nothing is blocked)"
        strong: true
      }
      Lbl {
        p: root.p
        width: parent.width
        dim: true
        wrapMode: Text.WordWrap
        maximumLineCount: 3
        font.pixelSize: Style.font.caption
        text: root.s.enforce && root.s.enforceActive
          ? "Blocked connections are dropped by nftables" + (root.s.enforceAppliedAt ? ", updated " + Model.ago(root.s.enforceAppliedAt, root.s.now) : "")
            + (root.s.enforceDrops > 0 ? ", " + root.s.enforceDrops + " packets stopped" : "")
            + ". Only your own apps are filtered; system services always pass."
          : "Turn on to actually drop what you block. Emergency off in any terminal: citadel-off"
      }
      Lbl {
        p: root.p
        width: parent.width
        visible: root.s.enforceError !== ""
        color: root.p.urgent
        wrapMode: Text.WordWrap
        maximumLineCount: 4
        font.pixelSize: Style.font.caption
        text: root.s.enforceError
      }
    }
    ToggleSwitch {
      checked: root.s.enforce
      busy: root.s.enforceBusy
      interactive: root.s.helperInstalled
      foreground: root.p.foreground
      onToggled: root.s.setEnforce(!root.s.enforce)
    }
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: root.s.helperInstalled && !root.s.inWheel
    color: root.p.urgent
    wrapMode: Text.WordWrap
    maximumLineCount: 4
    font.pixelSize: Style.font.caption
    text: "You are not in the wheel group, so every change asks for an admin password. To avoid that: sudo usermod -aG wheel $USER, then log in again."
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: root.s.helperInstalled && root.s.helperOutdated
    color: root.p.urgent
    wrapMode: Text.WordWrap
    maximumLineCount: 5
    font.pixelSize: Style.font.caption
    text: "Security update: citadel-helper " + root.s.helperVersion + " " + root.s.helperProblem
          + " (other programs could use it to close other users' connections). Update it:\n"
          + "cd citadel-helper && git pull && makepkg -si"
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: !root.s.helperInstalled
    color: root.p.urgent
    wrapMode: Text.WordWrap
    maximumLineCount: 4
    font.pixelSize: Style.font.caption
    text: "Blocking needs citadel-helper. Build and install it once:\n"
          + "git clone https://github.com/NeatOuk/citadel-helper.git && cd citadel-helper && makepkg -si"
  }

  Toggle {
    width: parent.width
    label: "Catch short connections"
    description: root.s.prefs.catchShort === false ? "Off: connections that end within a second may go unseen."
      : !root.s.enforce ? "Needs enforcement on. The helper then logs each new connection so none slip past."
      : !root.s.helperSupportsShort ? "Needs citadel-helper 1.2 or newer (installed: " + (root.s.helperVersion || "unknown") + ")."
      : root.s.kernelLog.error ? "Kernel log unavailable: " + root.s.kernelLog.error
      : root.s.helperLogging ? "On: " + root.s.kernelLog.seen + " new connections seen since start. Logged rate-limited to the kernel log."
      : "Turning on…"
    checked: root.s.prefs.catchShort !== false
    foreground: root.p.foreground
    fontFamily: root.p.fontFamily
    onClicked: root.s.setPref("catchShort", root.s.prefs.catchShort === false)
  }

  // ---------------------------------------------------------------- proxies
  PanelSeparator { foreground: root.p.foreground }
  PanelSectionHeader { text: "PROXIES"; foreground: root.p.foreground; fontFamily: root.p.fontFamily }
  Lbl {
    p: root.p
    width: parent.width
    dim: true
    wrapMode: Text.WordWrap
    maximumLineCount: 4
    font.pixelSize: Style.font.caption
    text: "In Policies, “Allow via proxy” sends an app through one of these. If a proxy is down, those connections are blocked, never sent direct."
          + (!root.s.enforce ? " Routing needs enforcement on." : "")
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: root.s.proxyError !== ""
    color: root.p.urgent
    wrapMode: Text.WordWrap
    maximumLineCount: 4
    font.pixelSize: Style.font.caption
    text: root.s.proxyError
  }
  Repeater {
    model: root.s.proxies
    delegate: Column {
      required property var modelData
      readonly property var st: root.s.proxyStatus[modelData.id] || null
      readonly property var ck: root.s.proxyCheck[modelData.id] || null
      width: root.width
      spacing: Style.space(2)
      RowLayout {
        width: parent.width
        spacing: Style.space(8)
        Rectangle {
          width: Style.space(7); height: width; radius: width / 2
          color: !parent.parent.st ? root.p.dim : parent.parent.st.ok ? root.p.foreground : root.p.urgent
        }
        Column {
          Layout.fillWidth: true
          Lbl { p: root.p; width: parent.width; strong: true; text: modelData.name }
          Lbl {
            p: root.p
            width: parent.width
            dim: true
            font.pixelSize: Style.font.caption
            elide: Text.ElideRight
            text: modelData.type.toUpperCase() + " " + modelData.host + ":" + modelData.port
                  + (modelData.auth ? " · login in keyring" : "")
                  + " · " + (!parent.parent.parent.st ? "checking…"
                             : parent.parent.parent.st.ok ? "reachable, " + parent.parent.parent.st.ms + " ms"
                             : parent.parent.parent.st.error)
          }
        }
        LinkButton { p: root.p; text: "Check"; onClicked: root.s.checkProxy(modelData.id) }
        LinkButton { p: root.p; text: "Edit"; onClicked: root.editProxy(modelData) }
        LinkButton { p: root.p; danger: true; text: "Remove"; onClicked: root.s.removeProxy(modelData.id) }
      }
      Lbl {
        p: root.p
        visible: !!parent.ck
        leftPadding: Style.space(15)
        font.pixelSize: Style.font.caption
        color: parent.ck && parent.ck.ok === false ? root.p.urgent : root.p.dim
        text: !parent.ck ? "" : parent.ck.pending ? "Testing a connection through it…"
              : parent.ck.ok ? "Test connection worked (" + parent.ck.ms + " ms)" : "Test failed: " + parent.ck.error
      }
    }
  }

  // add / edit
  property string pxEdit: ""
  property string pxType: "http"
  property bool pxVerify: true
  property string pxMessage: ""
  function editProxy(x) {
    pxEdit = x.id; pxType = x.type; pxVerify = x.verifyTls !== false
    pxName.text = x.name; pxHost.text = x.host; pxPort.text = String(x.port); pxUser.text = ""; pxPass.text = ""
    pxMessage = x.auth ? "Leave username empty to keep the saved login." : ""
  }
  function clearProxyForm() {
    pxEdit = ""; pxType = "http"; pxVerify = true
    pxName.text = ""; pxHost.text = ""; pxPort.text = ""; pxUser.text = ""; pxPass.text = ""
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(6)
    TextField { id: pxName; Layout.fillWidth: true; placeholderText: "name (e.g. Office)"; foreground: root.p.foreground }
    ButtonGroup {
      options: [{ value: "http", label: "HTTP" }, { value: "https", label: "HTTPS" }, { value: "socks5", label: "SOCKS5" }]
      value: root.pxType
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.pxType = v }
    }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(6)
    TextField { id: pxHost; Layout.fillWidth: true; placeholderText: "proxy host or IP"; foreground: root.p.foreground }
    TextField { id: pxPort; Layout.preferredWidth: Style.space(70); placeholderText: "port"; foreground: root.p.foreground }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(6)
    TextField { id: pxUser; Layout.fillWidth: true; placeholderText: "username (optional)"; foreground: root.p.foreground }
    TextField { id: pxPass; Layout.fillWidth: true; placeholderText: "password"; password: true; foreground: root.p.foreground }
  }
  Toggle {
    width: parent.width
    visible: root.pxType === "https"
    label: "Verify the proxy's TLS certificate"
    description: "Turn off only for a proxy with a self-signed certificate you trust"
    checked: root.pxVerify
    foreground: root.p.foreground
    fontFamily: root.p.fontFamily
    onClicked: root.pxVerify = !root.pxVerify
  }
  RowLayout {
    width: parent.width
    Lbl { p: root.p; Layout.fillWidth: true; dim: true; text: root.pxMessage; font.pixelSize: Style.font.caption }
    Button {
      visible: root.pxEdit !== ""
      text: "Cancel"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      onClicked: { root.clearProxyForm(); root.pxMessage = "" }
    }
    Button {
      text: root.pxEdit ? "Save proxy" : "Add proxy"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: {
        var err = root.s.saveProxy({ id: root.pxEdit, name: pxName.text, type: root.pxType, host: pxHost.text,
                                     port: pxPort.text, verifyTls: root.pxVerify },
                                   pxUser.text.trim(), pxPass.text)
        root.pxMessage = err || (root.pxEdit ? "Proxy saved." : "Proxy added.")
        if (!err) root.clearProxyForm()
      }
    }
  }
  Dropdown {
    id: defaultRouteDrop
    width: parent.width
    visible: root.s.proxies.length > 0
    label: "Everything else"
    value: root.s.defaultRoute
    options: [{ value: "direct", label: "Direct" }].concat(root.s.proxies.map(function(x) { return { value: x.id, label: "via " + x.name } }))
    foreground: root.p.foreground
    onChanged: function(v) { root.s.setDefaultRoute(v) }
  }
  Repeater {
    model: root.s.proxyLog.slice(0, 5)
    delegate: Lbl {
      required property var modelData
      p: root.p
      width: root.width
      color: root.p.urgent
      font.pixelSize: Style.font.caption
      elide: Text.ElideRight
      text: Model.clock(modelData.ts) + "  blocked " + modelData.dst + ":" + modelData.port + " (via " + modelData.proxy + "): " + modelData.error
    }
  }

  // ---------------------------------------------------------------- mode
  PanelSeparator { foreground: root.p.foreground }
  PanelSectionHeader { text: "OPEN AND LOCKDOWN"; foreground: root.p.foreground; fontFamily: root.p.fontFamily }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl { p: root.p; dim: true; text: "Last"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      options: [{ value: "0", label: "Until I change it" }, { value: "15", label: "15 min" }, { value: "60", label: "1 hour" }]
      value: String(root.s.prefs.modeMinutes || 0)
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) {
        root.s.setPref("modeMinutes", Number(v))
        if (root.s.mode !== "guarded") root.s.setMode(root.s.mode, Number(v))
      }
    }
  }
  Lbl {
    p: root.p
    width: parent.width
    dim: true
    wrapMode: Text.WordWrap
    maximumLineCount: 3
    font.pixelSize: Style.font.caption
    text: root.s.mode === "guarded" ? "Guarded: new connections without a policy wait at the gate."
        : (root.s.mode === "open" ? "Open: new connections pass without asking and are logged."
           : "Lockdown: anything without an allow policy is blocked" + (root.s.enforce ? "." : " (turn enforcement on to make it stick).") )
          + (root.s.silentUntil > 0 ? " Back to Guarded at " + Model.clock(root.s.silentUntil) + "." : "")
  }

  // ---------------------------------------------------------------- profiles
  PanelSeparator { foreground: root.p.foreground }
  PanelSectionHeader { text: "ZONES"; foreground: root.p.foreground; fontFamily: root.p.fontFamily }
  Lbl {
    p: root.p
    width: parent.width
    dim: true
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
    maximumLineCount: 3
    text: "In the " + root.s.activeProfile + " zone" + (root.s.profileOverride ? " (chosen by you)" : " (automatic)")
          + " · on " + ((root.s.network.names || []).join(", ") || "no network")
          + ". Link networks to a zone and Citadel switches zones as you move."
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: (root.s.network.source || "none") === "none"
    color: root.p.urgent
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
    maximumLineCount: 3
    text: "Zones can't switch on their own: neither NetworkManager nor iwd is running, and no wired link is up. Pick a zone by hand above."
  }
  Lbl {
    p: root.p
    width: parent.width
    visible: root.s.network.source === "iwd" || root.s.network.source === "interfaces"
    dim: true
    font.pixelSize: Style.font.caption
    text: root.s.network.source === "iwd" ? "Networks are read from iwd (Wi-Fi names) and your wired interfaces."
                                          : "Only wired interfaces are visible; Wi-Fi names need NetworkManager or iwd."
  }
  ButtonGroup {
    options: [{ value: "", label: "Automatic" }].concat(root.s.profiles.map(function(pr) { return { value: pr.name, label: pr.name } }))
    value: root.s.profileOverride
    foreground: root.p.foreground
    fontFamily: root.p.fontFamily
    fontSize: Style.font.caption
    onChanged: function(v) { root.s.setProfileOverride(v) }
  }
  Repeater {
    model: root.s.profiles
    delegate: Column {
      required property var modelData
      readonly property var nets: {
        var all = (modelData.networks || []).slice()
        ;(root.s.network.names || []).forEach(function(n) { if (all.indexOf(n) === -1) all.push(n) })
        return all
      }
      width: root.width
      spacing: Style.space(3)
      RowLayout {
        width: parent.width
        Lbl {
          p: root.p
          Layout.fillWidth: true
          text: modelData.name + (modelData.name === root.s.activeProfile ? "  ●" : "")
          strong: true
        }
        LinkButton {
          p: root.p
          danger: true
          visible: root.s.profiles.length > 1
          text: "Remove"
          onClicked: root.s.removeProfile(modelData.name)
        }
      }
      Flow {
        width: parent.width
        spacing: Style.space(6)
        Repeater {
          model: parent.parent.nets
          delegate: Button {
            required property var modelData
            readonly property bool linked: (parent.parent.modelData.networks || []).indexOf(modelData) !== -1
            text: (linked ? "✓ " : "+ ") + modelData
            selected: linked
            foreground: root.p.foreground
            fontSize: Style.font.caption
            bordered: true
            onClicked: root.s.toggleProfileNetwork(parent.parent.modelData.name, modelData)
          }
        }
        Lbl {
          p: root.p
          visible: parent.parent.nets.length === 0
          dim: true
          text: "No networks yet"
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(6)
    TextField {
      id: profileName
      Layout.fillWidth: true
      placeholderText: "new zone (e.g. Public, Work)"
      foreground: root.p.foreground
      onAccepted: { root.s.addProfile(text); text = "" }
    }
    Button {
      text: "Add zone"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: { root.s.addProfile(profileName.text); profileName.text = "" }
    }
  }

  // ---------------------------------------------------------------- alerts
  PanelSeparator { foreground: root.p.foreground }
  PanelSectionHeader { text: "THE GATE"; foreground: root.p.foreground; fontFamily: root.p.fontFamily }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl { p: root.p; dim: true; text: "No verdict?"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      options: [{ value: "allow", label: "Allow once" }, { value: "deny", label: "Block once" }]
      value: root.s.prefs.alertDefault === "deny" ? "deny" : "allow"
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.s.setPref("alertDefault", v) }
    }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl { p: root.p; dim: true; text: "after"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      options: [{ value: "30", label: "30 s" }, { value: "90", label: "90 s" }, { value: "300", label: "5 min" },
                { value: "0", label: "Never" }]
      value: String(root.s.prefs.alertTimeout)
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.s.setPref("alertTimeout", Number(v)) }
    }
  }
  Toggle {
    width: parent.width
    label: "Desktop notifications"
    description: "Also send a notification when something arrives at the gate; click it to decide"
    checked: root.s.prefs.notify !== false
    foreground: root.p.foreground
    fontFamily: root.p.fontFamily
    onClicked: root.s.setPref("notify", root.s.prefs.notify === false)
  }

  // ---------------------------------------------------------------- explain
  PanelSeparator { foreground: root.p.foreground }
  PanelSectionHeader { text: "EXPLAIN"; foreground: root.p.foreground; fontFamily: root.p.fontFamily }
  Lbl {
    p: root.p
    width: parent.width
    dim: true
    wrapMode: Text.WordWrap
    maximumLineCount: 5
    font.pixelSize: Style.font.caption
    text: (root.s.explainCustom ? "Explain asks your custom command below."
           : root.s.defaultAgent ? "Explain asks your Omarchy default agent, " + root.s.defaultAgent + ", when you press it at the gate."
           : "No Omarchy default agent is set (omarchy agent --pick), so Explain is off until you set one or a custom command.")
          + " It sends the app, the destination and the masked command line; a cloud agent sends them to its provider."
  }
  TextField {
    width: parent.width
    placeholderText: "model (optional, e.g. a small fast one; blank = the agent's default)"
    text: root.s.prefs.explainModel || ""
    foreground: root.p.foreground
    onEditingFinished: if (text.trim() !== (root.s.prefs.explainModel || "")) root.s.setPref("explainModel", text.trim())
  }
  TextField {
    width: parent.width
    placeholderText: "custom command (optional), e.g. mytool --print {prompt}"
    text: root.s.prefs.explainCommand || ""
    foreground: root.p.foreground
    onEditingFinished: if (text.trim() !== (root.s.prefs.explainCommand || "")) root.s.setPref("explainCommand", text.trim())
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl {
      p: root.p
      Layout.fillWidth: true
      readonly property var t: root.s.explainTestResult
      color: t.state === "error" ? root.p.urgent : root.p.foreground
      dim: t.state !== "error"
      wrapMode: Text.WordWrap
      maximumLineCount: 3
      font.pixelSize: Style.font.caption
      text: t.state === "pending" ? "Asking " + t.agent + "…"
            : t.state === "error" ? t.error
            : t.state === "done" ? "OK, " + t.agent + (t.model ? " · " + t.model : "") + ": " + t.result.service + " · " + t.result.company
            : ""
    }
    Button {
      text: "Test"
      enabled: root.s.explainAvailable && root.s.explainTestResult.state !== "pending"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: root.s.testExplain()
    }
  }

  // ---------------------------------------------------------------- data
  PanelSeparator { foreground: root.p.foreground }
  PanelSectionHeader { text: "DATA"; foreground: root.p.foreground; fontFamily: root.p.fontFamily }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl { p: root.p; dim: true; text: "Refresh every"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      options: [{ value: "1", label: "1 s" }, { value: "2", label: "2 s" }, { value: "5", label: "5 s" }]
      value: String(root.s.prefs.interval)
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.s.setPref("interval", Number(v)) }
    }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl { p: root.p; dim: true; text: "Keep history"; font.pixelSize: Style.font.caption }
    ButtonGroup {
      options: [{ value: "7", label: "7 days" }, { value: "30", label: "30 days" }, { value: "90", label: "90 days" }]
      value: String(root.s.prefs.retentionDays)
      foreground: root.p.foreground
      fontFamily: root.p.fontFamily
      fontSize: Style.font.caption
      onChanged: function(v) { root.s.setPref("retentionDays", Number(v)) }
    }
  }
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    Lbl {
      p: root.p
      Layout.fillWidth: true
      dim: true
      wrapMode: Text.WordWrap
      maximumLineCount: 2
      font.pixelSize: Style.font.caption
      text: root.s.geoip.installed ? (root.s.geoip.owner ? "Country and network-owner databases" : "Country database") + " installed (DB-IP Lite, CC BY 4.0), " + Model.ago(root.s.geoip.updated || 0, root.s.now)
          : root.s.geoip.error ? "Country database: " + root.s.geoip.error : "Country database not installed"
    }
    Button {
      text: root.s.geoip.downloading ? "Downloading…" : root.s.geoip.installed ? "Update" : "Download"
      foreground: root.p.foreground
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: root.s.downloadGeoip()
    }
  }
}
