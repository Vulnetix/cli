const CryptoJS = require("crypto-js");

function encryptBackup(data, password) {
  return CryptoJS.AES.encrypt(JSON.stringify(data), password).toString();
}

function fieldId(passwordFieldId) {
  return btoa(passwordFieldId);
}

module.exports = { encryptBackup, fieldId };
