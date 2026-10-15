const crypto = require("crypto");
const CryptoJS = require("crypto-js");

function persist(req, key, iv) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
~>  let enc = cipher.update(req.body.password, "utf8", "hex");
  enc += cipher.final("hex");
~>  const legacy = CryptoJS.AES.encrypt(this.password, key).toString();
~>  const shown = Buffer.from(newPassword, "utf8").toString("base64");
  return db.save({ enc, legacy, shown });
}
