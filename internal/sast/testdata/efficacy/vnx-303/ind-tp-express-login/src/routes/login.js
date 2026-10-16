const express = require('express');
const bcrypt = require('bcrypt');
const { User } = require('../models');

const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await User.findOne({ where: { email: req.body.email } });
~>  if (user && bcrypt.compare(req.body.password, user.passwordHash)) {
    req.session.userId = user.id;
    return res.redirect('/dashboard');
  }
  res.status(401).render('login', { error: 'Invalid credentials' });
});

module.exports = router;
