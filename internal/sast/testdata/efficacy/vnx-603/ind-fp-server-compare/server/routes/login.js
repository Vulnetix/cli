const express = require('express');
const bcrypt = require('bcrypt');
const { User } = require('../models');

const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await User.findOne({ where: { email: req.body.email } });
  const password = req.body.password;
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'invalid' });
  }
  if (req.body.pin === '0000') {
    return res.status(400).json({ error: 'choose another PIN' });
  }
  req.session.userId = user.id;
  res.json({ ok: true });
});

module.exports = router;
