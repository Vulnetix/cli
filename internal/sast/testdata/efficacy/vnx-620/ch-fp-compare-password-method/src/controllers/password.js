const User = require('../models/user');

async function changePassword(req, res) {
  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user.id).select('+password');
  const ok = await user.comparePassword(oldPassword);
  if (!ok) {
    return res.status(401).json({ error: 'current password is wrong' });
  }
  user.password = newPassword;
  await user.save();
  return res.status(204).end();
}

module.exports = { changePassword };
