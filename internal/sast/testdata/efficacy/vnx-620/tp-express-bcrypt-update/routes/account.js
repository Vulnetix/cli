const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

router.post('/account/change-password', requireLogin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 12) {
    return res.status(400).send('too short');
  }
  const user = await User.findById(req.user.id);
~>  user.password = await bcrypt.hash(newPassword, 12);
  await user.save();
  res.sendStatus(204);
});

router.put('/api/users/me/password', requireLogin, async (req, res) => {
  const hash = await bcrypt.hash(req.body.newPassword, 12);
~>  await User.updateOne({ _id: req.user.id }, { $set: { password: hash } });
  res.sendStatus(204);
});

module.exports = router;
