.pragma library
// One Citadel per shell. The bar puts this widget on every screen, and each
// copy used to run its own Service: two monitors, two proxies, and two policy
// sets fighting over the firewall and state.json. The first widget creates
// the Service; the others show that same one. A `.pragma library` script is
// shared by every importer in the engine.

var service = null

function alive(s) {
  // a destroyed QObject reads back as null/undefined properties
  try { return !!s && s.objectName === "citadel-service" } catch (e) { return false }
}
