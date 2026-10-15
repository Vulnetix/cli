const express = require('express');
const User = require('../models/user');

const router = express.Router();

router.get('/me', async (req, res) => {
  const user = await User.findById(req.session.userId);
~>  res.json({ id: user.id, email: user.email, password: user.password });
});

router.get('/keys', async (req, res) => {
  const acct = await Account.findOne({ owner: req.user.id });
~>  return res.send({ name: acct.name, apiKey: acct.apiKey });
});

module.exports = router;
