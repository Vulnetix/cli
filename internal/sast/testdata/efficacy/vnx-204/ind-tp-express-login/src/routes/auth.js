const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

const router = express.Router();

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
~>    return res.status(401).json({ message: 'No account found with that email' });
  }
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ message: 'Incorrect password' });
  }
  req.session.userId = user.id;
  return res.json({ ok: true });
});

module.exports = router;
