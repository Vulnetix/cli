const crypto = require("crypto");
const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });
const hmacKey = crypto.generateKeySync("hmac", { length: 512 });
module.exports = { ec, rsa, hmacKey };
