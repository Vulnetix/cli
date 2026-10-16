const fs = require("fs");
const os = require("os");
const path = require("path");

const credPath = path.join(os.homedir(), ".acme", "credentials.json");

function saveSession(accessToken) {
  fs.mkdirSync(path.dirname(credPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(credPath, JSON.stringify({ accessToken }), { mode: 0o600 });
}

function writeSummary(results) {
  fs.writeFileSync(path.join("out", "summary.json"), JSON.stringify(results, null, 2));
}

function loadSession() {
  return JSON.parse(fs.readFileSync(credPath, "utf8"));
}

module.exports = { saveSession, writeSummary, loadSession };
