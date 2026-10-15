const express = require('express');
const router = express.Router();
const User = require('../models/user');

router.post('/register', async (req, res) => {
  const user = new User({ email: req.body.email });
~>  if (req.body.isAdmin) user.roles.push('admin');
  await user.save();
  res.status(201).json({ id: user.id });
});

module.exports = router;
