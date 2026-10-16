const crypto = require("crypto");
const CryptoJS = require("crypto-js");

function storeLegacy(user, password) {
~>  user.secret = CryptoJS.AES.encrypt(password, process.env.APP_KEY).toString();
  return user.save();
}

function storeEncoded(user) {
~>  user.passwordBlob = Buffer.from(user.password).toString("base64");
  return user.save();
}

function encryptForVault(newPassword, key, iv) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
~>  let enc = cipher.update(newPassword, "utf8", "hex");
  enc += cipher.final("hex");
  return enc;
}

module.exports = { storeLegacy, storeEncoded, encryptForVault };
