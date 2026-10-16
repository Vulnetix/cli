const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/user');

const router = express.Router();

~>router.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.hash))) {
    return res.status(401).json({ error: 'bad credentials' });
  }
  res.json({ token: sign(user) });
});

module.exports = router;
