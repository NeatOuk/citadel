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
    text: "Security update: citadel-helper " + root.s.helperVersion + " is older than " + root.s.minHelper
          + ", which fixes a way for other programs to close other users' connections. Update it:\n"
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
      text: root.s.geoip.installed ? "Country database installed (DB-IP Lite, CC BY 4.0), " + Model.ago(root.s.geoip.updated || 0, root.s.now)
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
