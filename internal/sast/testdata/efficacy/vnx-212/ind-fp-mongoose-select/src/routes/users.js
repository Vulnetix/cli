const express = require('express');
const User = require('../models/User');

const router = express.Router();

router.get('/:id', async (req, res) => {
  const user = await User.findById(req.params.id).select('-password -resetToken');
  if (!user) return res.sendStatus(404);
  res.json(user);
});

router.get('/:id/public', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user.toPublicJSON());
});

module.exports = router;
