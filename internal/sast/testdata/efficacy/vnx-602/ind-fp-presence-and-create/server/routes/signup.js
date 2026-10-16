const express = require('express');
const { User } = require('../models');

const router = express.Router();

router.post('/invite', async (req, res) => {
  if (req.body.role === undefined || req.body.role === null) {
    return res.status(400).json({ error: 'role is required' });
  }
  const user = await User.create({ email: req.body.email, role: req.body.role });
  res.status(201).json({ id: user.id });
});

module.exports = router;
