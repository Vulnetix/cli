const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

const router = express.Router();
const INVALID = 'Invalid email or password';

router.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(401).json({ message: INVALID });
  }
  if (!(await bcrypt.compare(req.body.password, user.passwordHash))) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }
  return res.json({ ok: true });
});

module.exports = router;
