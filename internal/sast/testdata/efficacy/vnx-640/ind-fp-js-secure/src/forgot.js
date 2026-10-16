const crypto = require('crypto');

exports.forgot = async (req, res) => {
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetPasswordExpires = Date.now() + 3600000;
  const delay = Math.random() * 100;
  await save(req.body.email, resetToken, resetPasswordExpires);
  res.sendStatus(204);
};
