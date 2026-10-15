const path = require("path");
const ROOT = path.resolve("public");

function locate(rel) {
  const full = path.join(ROOT, rel);
  if (!full.startsWith(ROOT + path.sep)) {
    throw new Error("forbidden");
  }
  return full;
}

function isSecure(host) {
  const url = "https://" + host;
  return url.startsWith("https://");
}

module.exports = { locate, isSecure };
