const crypto = require("crypto");
const fs = require("fs");

let lastHash = null;

function onChange(file, rebuild) {
  const contentHash = crypto.createHash("sha1").update(fs.readFileSync(file)).digest("hex");
  if (lastHash && contentHash !== lastHash) {
    rebuild(file);
  }
  lastHash = contentHash;
}

function scrollToAnchor() {
  const { hash } = useLocation();
  if (hash && hash !== window.__lastAnchor) {
    document.getElementById(hash.slice(1)).scrollIntoView();
  }
}

module.exports = { onChange, scrollToAnchor };
