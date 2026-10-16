const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/user');
const { requireLogin } = require('../middleware/auth');

const router = express.Router();

router.post('/change-password', requireLogin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 10) {
    return res.status(400).json({ error: 'Password too short' });
  }
  const hash = await bcrypt.hash(newPassword, 12);
~>  await User.updateOne({ _id: req.user.id }, { $set: { password: hash } });
  res.json({ ok: true });
});

module.exports = router;
