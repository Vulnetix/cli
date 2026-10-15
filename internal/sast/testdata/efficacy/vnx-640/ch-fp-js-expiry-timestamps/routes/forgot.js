const crypto = require("crypto");

async function forgot(user) {
  const resetToken = crypto.randomBytes(20).toString("hex");
  user.resetPasswordToken = resetToken;
  user.resetPasswordExpires = Date.now() + 3600000;
  user.resetTokenSentAt = new Date().getTime();
  await user.save();
}
