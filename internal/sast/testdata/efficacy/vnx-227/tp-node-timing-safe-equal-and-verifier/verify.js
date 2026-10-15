const crypto = require("crypto");
const bcrypt = require("bcrypt");

async function login(user, password) {
~>  await bcrypt.compare(password, user.hash);
  return issueToken(user);
}

function checkSignature(payload, signature, publicKey) {
  const verifier = crypto.createVerify("SHA256");
  verifier.update(payload);
~>  verifier.verify(publicKey, signature, "base64");
~>  crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected(payload)));
  return JSON.parse(payload);
}
