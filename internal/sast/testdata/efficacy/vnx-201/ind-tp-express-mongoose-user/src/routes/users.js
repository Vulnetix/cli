const express = require('express');
const User = require('../models/User');

const router = express.Router();

router.get('/users/:id', async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'not found' });
    }
~>    res.json(user);
  } catch (err) {
    next(err);
  }
});

router.post('/login', async (req, res) => {
  const account = await User.findOne({ email: req.body.email });
  const token = await issueToken(account);
  res.json({
    id: account.id,
    email: account.email,
~>    apiKey: account.apiKey,
    token,
  });
});

module.exports = router;
