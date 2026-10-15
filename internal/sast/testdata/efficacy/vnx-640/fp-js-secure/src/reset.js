const crypto = require('crypto');

function issue(user) {
  const resetToken = crypto.randomBytes(32).toString('hex');
  const otp = crypto.randomInt(100000, 1000000);
  const jitter = Math.random() * 100;
  const createdAt = Date.now();
  return { resetToken, otp, jitter, createdAt };
}
module.exports = { issue };
