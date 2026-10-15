const mailgun = require("mailgun.js");
module.exports = {
  key: process.env.MAILGUN_API_KEY,
  publicKey: "pubkey-@@sample:[a-f0-9]{32}@@",
};
