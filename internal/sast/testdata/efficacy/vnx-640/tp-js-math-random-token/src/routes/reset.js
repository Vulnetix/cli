const crypto = require('crypto');

async function forgot(req, res) {
  const user = await User.findOne({ email: req.body.email });
~>  const resetToken = Math.random().toString(36).slice(2);
~>  user.passwordResetCode = Date.now().toString(16);
  await user.save();
  await mail.send(user.email, `https://app.example/reset/${resetToken}`);
  res.status(202).end();
}

function makeOtp() {
  return {
~>    otp: Math.floor(Math.random() * 1000000),
  };
}
module.exports = { forgot, makeOtp };
