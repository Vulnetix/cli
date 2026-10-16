const User = require('./models/user');
const mailer = require('./mailer');

async function forgotPassword(req, res) {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(204).end();
~>  const resetToken = Math.random().toString(36).slice(2);
  user.resetPasswordToken = resetToken;
  user.resetPasswordExpires = Date.now() + 3600000;
  await user.save();
~>  const resetUrl = `${req.protocol}://${req.headers.host}/reset/${resetToken}`;
  await mailer.send(user.email, 'Password reset', resetUrl);
  res.status(204).end();
}

function makeOtp() {
~>  const otp = Math.floor(100000 + Math.random() * 900000);
  return String(otp);
}

module.exports = { forgotPassword, makeOtp };
