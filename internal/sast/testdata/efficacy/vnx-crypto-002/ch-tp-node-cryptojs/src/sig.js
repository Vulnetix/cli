const CryptoJS = require("crypto-js");
const sha1 = require("sha1");

~>exports.sign = (body, key) => CryptoJS.SHA1(body + key).toString();
~>exports.token = (u) => sha1(u.id + process.env.SECRET);
