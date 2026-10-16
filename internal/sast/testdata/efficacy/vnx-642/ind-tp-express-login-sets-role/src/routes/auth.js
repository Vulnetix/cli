const express = require('express');
const bcrypt = require('bcrypt');
const { User } = require('../models');

const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await User.findOne({ where: { email: req.body.email } });
  if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  req.session.userId = user.id;
~>  res.cookie('user_role', user.role, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000,
  });
  res.json({ ok: true });
});

module.exports = router;
