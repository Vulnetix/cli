const md5 = require("md5");
const CryptoJS = require("crypto-js");

function apiToken(user) {
~>  return md5(user.email + process.env.SECRET);
}

function sig(body, key) {
~>  return CryptoJS.MD5(body + key).toString();
}

module.exports = { apiToken, sig };
