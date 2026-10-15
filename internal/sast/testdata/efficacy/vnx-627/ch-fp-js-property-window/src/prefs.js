const STORAGE_KEY = "prefs";

function load(req, res) {
  const prefs = window[STORAGE_KEY];
  const settings = config.global[req.query.key];
  const label = labels[req.query.key];
  // window[req.query.name] would be dangerous
  res.json({ prefs, settings, label, hint: "global[req.query.x]" });
}

module.exports = { load };
