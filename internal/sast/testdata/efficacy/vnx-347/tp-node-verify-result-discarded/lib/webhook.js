const crypto = require("crypto");

function acceptRelease(manifest, signature, publicKey) {
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(manifest);
~>  verifier.verify(publicKey, signature, "base64");
  return JSON.parse(manifest);
}

function acceptEd(data, sig, key) {
~>  crypto.verify(null, Buffer.from(data), key, Buffer.from(sig, "hex"));
  return data;
}

function hook(req) {
  const digest = crypto.createHmac("sha256", secret).update(req.rawBody).digest();
~>  crypto.timingSafeEqual(digest, Buffer.from(req.get("X-Signature"), "hex"));
  return handle(req.body);
}

async function acceptBrowser(key, sig, data) {
~>  await crypto.subtle.verify("Ed25519", key, sig, data);
  return data;
}
