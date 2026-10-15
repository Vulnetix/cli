const crypto = require("crypto");
const hasEcb = crypto.getCiphers().includes("aes-128-ecb");
module.exports = { hasEcb };
