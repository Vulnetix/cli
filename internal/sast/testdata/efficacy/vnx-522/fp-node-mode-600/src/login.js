const fs = require("fs");

function saveSession(credPath, accessToken) {
  fs.writeFileSync(credPath, JSON.stringify({ accessToken }), { mode: 0o600 });
}

function saveKey(keyFile, apiKey) {
  fs.writeFileSync(keyFile, apiKey, {
    encoding: "utf8",
    mode: 0o600,
  });
}

function writeLog(out, text) {
  fs.writeFileSync(out, text);
}
