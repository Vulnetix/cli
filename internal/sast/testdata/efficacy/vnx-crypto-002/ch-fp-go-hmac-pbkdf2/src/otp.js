const crypto = require("crypto");
exports.hotp = (key, counter) => crypto.createHmac("sha1", key).update(counter).digest();
