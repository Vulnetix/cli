const crypto = require('crypto');
const CryptoJS = require('crypto-js');

function hashPassword(password) {
~>  return crypto.createHash('sha256').update(password).digest('hex');
}

function legacyHash(user) {
  return crypto
    .createHash('md5')
~>    .update(user.password + user.salt)
    .digest('hex');
}

function twoLine(newPassword) {
  const hasher = crypto.createHash("sha1");
~>  hasher.update(newPassword);
  return hasher.digest("base64");
}

~>const browserHash = (pwd) => CryptoJS.SHA256(pwd).toString();
~>const otherHash = (form) => CryptoJS.MD5(form.password).toString();

module.exports = { hashPassword, legacyHash, twoLine, browserHash, otherHash };
