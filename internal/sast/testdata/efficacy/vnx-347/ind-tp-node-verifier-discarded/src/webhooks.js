const crypto = require("crypto");

function verifyRelease(manifest, signature, publicKey) {
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(manifest);
~>  verifier.verify(publicKey, signature, "base64");
  return JSON.parse(manifest);
}

function stripeHook(req, res) {
  const digest = crypto.createHmac("sha256", process.env.HOOK_SECRET).update(req.rawBody).digest();
~>  crypto.timingSafeEqual(digest, Buffer.from(req.get("X-Signature"), "hex"));
  res.sendStatus(200);
}

module.exports = { verifyRelease, stripeHook };
