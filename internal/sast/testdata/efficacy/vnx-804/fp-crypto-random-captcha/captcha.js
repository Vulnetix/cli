const crypto = require('crypto');

function generateCaptcha() {
  const code = crypto.randomInt(100000, 999999).toString();
  return code;
}
module.exports = { generateCaptcha };
