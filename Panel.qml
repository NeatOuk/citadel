import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model
import "views"

// Citadel: outbound firewall for the Omarchy bar. Bar tower icon, the
// "at the gate" card for new connections, and the panel with its tabs.
Panel {
  id: root
  moduleName: "neat.citadel"
  ipcTarget: "neat.citadel"
  manageIpc: false

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property string pluginDir: String(Qt.resolvedUrl(".")).replace(/^file:\/\//, "").replace(/\/$/, "")
  readonly property int waiting: citadel.alerts.length
  readonly property bool enforcing: citadel.enforce && citadel.enforceActive

  property string view: "traffic"
  property string cardDismissedKey: ""        // "Later" hides the card until the next request
  // A bool (not the popout object) so opening the card, which sets
  // bar.activePopout, doesn't re-trigger its own open condition.
  readonly property bool otherPopoutOpen: !!(bar && bar.activePopout && bar.activePopout !== gateCard)
  // Never take the bar's single popout slot from a panel the user has open.
  readonly property bool cardWanted: waiting > 0 && !opened && !otherPopoutOpen
                                     && cardDismissedKey !== citadel.alerts[0].key
  // Opening the card makes the bar update activePopout synchronously, so the
  // card's `open` is set one event later instead of bound (no binding loop).
  onCardWantedChanged: Qt.callLater(function() { gateCard.open = root.cardWanted })

  readonly property var modes: [
    { value: "guarded", label: "Guarded", tooltip: "Ask about every new connection" },
    { value: "open", label: "Open", tooltip: "Let everything through quietly (logged)" },
    { value: "lockdown", label: "Lockdown", tooltip: "Block everything you haven't allowed" }
  ]
  function modeLabel(m) {
    for (var i = 0; i < modes.length; i++) if (modes[i].value === m) return modes[i].label
    return m
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    panelFlick.contentY = 0
    citadel.requestStats()
    citadel.refreshEnforceStatus()
    if (waiting > 0) view = "gate"
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  Service {
    id: citadel
    settings: root.settings
    pluginDir: root.pluginDir
    onOpenRequested: function(v) { root.view = v; root.open() }
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function showView(name: string): void { root.view = name; root.open() }
    function setMode(mode: string, minutes: int): void { citadel.setMode(mode, minutes) }
    function lockdown(): void { citadel.setMode("lockdown", 0) }
    function guard(): void { citadel.setMode("guarded", 0) }
    function enforce(on: bool): void { citadel.setEnforce(on) }
    function addRule(json: string): string {
      try { return citadel.addRule(JSON.parse(json)).id } catch (e) { return "error: " + e }
    }
    function removeRule(id: string): void { citadel.removeRule(id) }
    function rules(): string { return JSON.stringify(citadel.rules) }
    function setList(id: string, on: bool): void { citadel.setListEnabled(id, on) }
    function lists(): string { return JSON.stringify({ lists: citadel.lists, status: citadel.listStatus, ipCidrs: citadel.ipCidrs.length }) }
    function downloadGeoip(): void { citadel.downloadGeoip() }
    function geoip(): string { return JSON.stringify(citadel.geoip) }
    function status(): string {
      return JSON.stringify({ mode: citadel.mode, zone: citadel.activeProfile, enforce: citadel.enforce,
                              enforceActive: citadel.enforceActive, waiting: citadel.alerts.length,
                              connections: citadel.totals.connections, policies: citadel.rules.length,
                              monitorUp: citadel.monitorUp, helperInstalled: citadel.helperInstalled,
                              enforceError: citadel.enforceError, drops: citadel.enforceDrops,
                              omarchy: citadel.omarchyVersion, omarchySupported: citadel.omarchySupported,
                              inWheel: citadel.inWheel, networkSource: citadel.network.source || "" })
    }
  }

  // ---------------------------------------------------------------- bar icon
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    iconComponent: Component {
      Item {
        CitadelIcon {
          anchors.centerIn: parent
          iconSize: Style.space(13)
          color: root.enforcing ? root.foreground : root.dim
          badgeColor: root.urgent
          mode: citadel.mode
          pendingCount: root.waiting
        }
      }
    }
    // right-click: quick Open for an hour, or back to Guarded
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) citadel.setMode(citadel.mode === "guarded" ? "open" : "guarded", citadel.mode === "guarded" ? 60 : 0)
      else root.toggle()
    }
  }

  // ---------------------------------------------------------------- gate card
  // Pops under the bar icon when a connection is waiting and the panel is
  // closed. Passive (no keyboard grab), so typing elsewhere is not stolen.
  PopupCard {
    id: gateCard
    anchorItem: button
    bar: root.bar
    owner: gateCard
    triggerMode: "hover"
    open: false                                  // driven by root.cardWanted
    contentWidth: gateCard.fittedContentWidth(Style.space(340))
    contentHeight: gateCard.fittedContentHeight(cardCol.implicitHeight, Style.space(520))
    function close() { if (root.waiting > 0) root.cardDismissedKey = citadel.alerts[0].key }

    Column {
      id: cardCol
      width: parent.width
      spacing: Style.space(8)
      RowLayout {
        width: parent.width
        spacing: Style.space(8)
        CitadelIcon {
          iconSize: Style.space(12)
          color: root.foreground
          mode: citadel.mode
        }
        Lbl {
          p: root
          Layout.fillWidth: true
          text: "AT THE GATE" + (root.waiting > 1 ? "   1 of " + root.waiting : "")
          strong: true
          font.pixelSize: Style.font.caption
          font.letterSpacing: 2
        }
        LinkButton { p: root; text: "Later"; onClicked: gateCard.close() }
        LinkButton { p: root; text: "All ▸"; onClicked: { root.view = "gate"; root.open() } }
      }
      VerdictCard {
        width: parent.width
        p: root
        s: citadel
        alert: root.waiting > 0 ? citadel.alerts[0] : null
      }
    }
  }

  // ---------------------------------------------------------------- panel
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(760))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onMoveRequested: function(dx, dy) {
        if (dy === 0) return
        var maxY = Math.max(0, panelFlick.contentHeight - panelFlick.height)
        panelFlick.contentY = Math.max(0, Math.min(maxY, panelFlick.contentY + dy * Style.space(60)))
      }
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: panelFlick.width - Style.space(6)
          spacing: Style.space(10)

          // ------------------------------------------------ header
          RowLayout {
            width: parent.width
            spacing: Style.space(12)
            CitadelIcon {
              iconSize: Style.space(30)
              color: root.enforcing ? root.foreground : root.dim
              badgeColor: root.urgent
              mode: citadel.mode
            }
            Column {
              Layout.fillWidth: true
              spacing: Style.space(3)
              Lbl {
                p: root
                text: "CITADEL"
                strong: true
                font.pixelSize: Style.font.title
                font.letterSpacing: 4
              }
              Lbl {
                p: root
                width: parent.width
                dim: true
                font.pixelSize: Style.font.caption
                text: root.modeLabel(citadel.mode)
                      + (citadel.silentUntil > 0 ? " until " + Model.clock(citadel.silentUntil) : "")
                      + "  ·  " + citadel.activeProfile + " zone"
                      + "  ·  " + (root.enforcing ? "enforcing" : "watching only")
              }
            }
          }
          ButtonGroup {
            options: root.modes
            value: citadel.mode
            foreground: root.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.caption
            focusable: false
            onChanged: function(v) { citadel.setMode(v, v === "guarded" ? 0 : Number(citadel.prefs.modeMinutes) || 0) }
          }

          PanelSeparator { foreground: root.foreground }
          ButtonGroup {
            options: [{ value: "gate", label: root.waiting > 0 ? "Gate · " + root.waiting : "Gate" },
                      { value: "traffic", label: "Traffic" }, { value: "policies", label: "Policies" },
                      { value: "history", label: "History" }, { value: "settings", label: "Settings" }]
            value: root.view
            foreground: root.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.bodySmall
            focusable: false
            onChanged: function(v) { root.view = v; panelFlick.contentY = 0; if (v === "history") citadel.requestStats() }
          }

          // ------------------------------------------------ views
          Column {
            visible: root.view === "gate"
            width: parent.width
            spacing: Style.space(14)
            Column {
              visible: root.waiting === 0
              width: parent.width
              spacing: Style.space(4)
              Lbl { p: root; text: "The gate is quiet."; strong: true }
              Lbl {
                p: root
                width: parent.width
                dim: true
                wrapMode: Text.WordWrap
                maximumLineCount: 3
                font.pixelSize: Style.font.caption
                text: citadel.mode === "guarded" ? "New connections without a policy will wait here for your verdict."
                    : citadel.mode === "open" ? "Open mode: new connections pass quietly and are logged in History."
                    : "Lockdown: anything without an allow policy is blocked."
              }
            }
            Repeater {
              model: root.view === "gate" ? citadel.alerts : []
              delegate: Column {
                required property var modelData
                required property int index
                width: column.width
                spacing: Style.space(10)
                PanelSeparator { visible: index > 0; foreground: root.foreground }
                VerdictCard { width: parent.width; p: root; s: citadel; alert: modelData }
              }
            }
          }
          TrafficView { visible: root.view === "traffic"; width: parent.width; p: root; s: citadel }
          PoliciesView { visible: root.view === "policies"; width: parent.width; p: root; s: citadel }
          HistoryView { visible: root.view === "history"; width: parent.width; p: root; s: citadel }
          SettingsView { visible: root.view === "settings"; width: parent.width; p: root; s: citadel }
        }
      }
    }
  }
}
