const crypto = require("crypto");
// never use aes-128-ecb here
const c = (k, iv) => crypto.createCipheriv("aes-256-gcm", k, iv);
module.exports = c;
