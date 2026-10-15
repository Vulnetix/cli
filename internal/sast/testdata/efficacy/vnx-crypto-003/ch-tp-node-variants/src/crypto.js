const crypto = require("crypto");
const ALGO = "aes-256-ecb";

function enc(key, data) {
~>  const c = crypto.createCipheriv(ALGO, key, null);
  return Buffer.concat([c.update(data), c.final()]);
}

function enc3(key, data) {
~>  const c = crypto.createCipheriv("des-ede3-ecb", key, "");
  return c.update(data);
}
