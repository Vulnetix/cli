const crypto = require("crypto");

function ok(signature, expected) {
  if (!signature || signature.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
module.exports = { ok };
