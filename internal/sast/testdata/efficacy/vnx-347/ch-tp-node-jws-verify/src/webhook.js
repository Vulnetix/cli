const jws = require("jws");
const crypto = require("crypto");

function receive(req, secret) {
  const signature = req.get("X-Signature");
~>  jws.verify(signature, "HS256", secret);
  return JSON.parse(jws.decode(signature).payload);
}

function check(req, secret) {
  if (!jws.verify(req.get("X-Signature"), "HS256", secret)) {
    throw new Error("bad signature");
  }
}
