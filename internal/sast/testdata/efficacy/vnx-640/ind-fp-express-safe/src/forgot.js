const crypto = require('crypto');
const config = require('./config');

async function forgotPassword(req, res) {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(204).end();
  const resetToken = crypto.randomBytes(32).toString('hex');
  const otp = crypto.randomInt(100000, 1000000);
  user.resetPasswordToken = resetToken;
  user.resetPasswordExpires = Date.now() + 3600000;
  await user.save();
  const resetUrl = `${config.publicBaseUrl}/reset/${resetToken}`;
  await mailer.send(user.email, 'Password reset', `${resetUrl} (${otp})`);
  res.status(204).end();
}

function retryDelay(attempt) {
  const jitter = Math.random() * 100;
  return Math.min(30000, 2 ** attempt * 100 + jitter);
}

function logRequest(req) {
  console.log('request from', req.headers.host, 'at', Date.now());
}

module.exports = { forgotPassword, retryDelay, logRequest };
