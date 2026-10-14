const jwt = require("jsonwebtoken");

~>const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\n@@sample:[A-Za-z0-9+/]{64}@@\r\n@@sample:[A-Za-z0-9+/]{64}@@\r\n-----END RSA PRIVATE KEY-----';

module.exports = (payload) => jwt.sign(payload, privateKey, { algorithm: "RS256" });
