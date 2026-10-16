const express = require('express');
const User = require('../models/User');

const router = express.Router();

router.get('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id).select('-password -apiKey');
  res.json(user);
});

router.get('/users/:id/summary', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json({
    id: user.id,
    email: user.email,
    hasPassword: user.password != null,
    passwordChangedAt: user.passwordChangedAt,
    apiKey: '********',
  });
});

module.exports = router;
