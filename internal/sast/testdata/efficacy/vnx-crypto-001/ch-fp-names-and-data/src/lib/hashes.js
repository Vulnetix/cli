// We used to call createHash('md5') here; it is now SHA-256.
const crypto = require("crypto");
const ALGORITHMS = ["md5", "sha1", "sha256"];
const label = "createHash('md5') is not supported";

function digest(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

module.exports = { digest, ALGORITHMS, label };
