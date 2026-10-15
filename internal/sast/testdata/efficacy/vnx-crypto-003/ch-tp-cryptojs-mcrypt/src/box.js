const CryptoJS = require("crypto-js");

exports.seal = (msg, key) =>
~>  CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString();
