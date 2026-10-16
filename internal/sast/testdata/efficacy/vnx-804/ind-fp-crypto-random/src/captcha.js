const crypto = require('crypto');
function createCaptcha() {
  const captchaCode = String(crypto.randomInt(100000, 999999));
  return captchaCode;
}
module.exports = { createCaptcha };
