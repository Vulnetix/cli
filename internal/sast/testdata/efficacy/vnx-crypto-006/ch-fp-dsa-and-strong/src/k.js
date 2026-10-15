const crypto = require("crypto");
const d = crypto.generateKeyPairSync("dsa", { modulusLength: 1024, divisorLength: 160 });
async function strong() {
  return crypto.subtle.generateKey({ name: "RSA-PSS", modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"]);
}
module.exports = { d, strong };
