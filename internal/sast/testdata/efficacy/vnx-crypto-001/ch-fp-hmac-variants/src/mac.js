const crypto = require("crypto");

module.exports = (key, msg) => crypto.createHmac("md5", key).update(msg).digest("hex");
