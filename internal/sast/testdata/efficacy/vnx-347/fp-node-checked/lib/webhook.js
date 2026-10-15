const crypto = require("crypto");
const jwt = require("jsonwebtoken");

function accept(manifest, signature, publicKey) {
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(manifest);
  if (!verifier.verify(publicKey, signature, "base64")) throw new Error("bad signature");
  const ok = crypto.verify(null, Buffer.from(manifest), publicKey, signature);
  crypto.verify(null, Buffer.from(manifest), publicKey, signature, (err, valid) => {
    if (!valid) reject();
  });
  jwt.verify(token, publicKey);
  return ok && crypto.timingSafeEqual(a, b);
}
