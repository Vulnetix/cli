const fs = require("fs");

function saveToken(file, token) {
  fs.writeFileSync(file, token, { mode: 0o600 });
}

function saveCredentials(file, creds) {
  fs.writeFileSync(file, JSON.stringify(creds));
  fs.chmodSync(file, 0o600);
}

function saveReadme(file) {
  fs.writeFileSync("README-password-policy.md", "Use a long password");
}
