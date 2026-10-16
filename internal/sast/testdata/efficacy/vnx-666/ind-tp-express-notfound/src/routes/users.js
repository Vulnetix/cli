const express = require('express');
const router = express.Router();
const { User } = require('../models');

router.get('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  if (!user) {
~>    res.status(404).json({ error: 'not found' });
  }
  user.lastSeen = new Date();
  await user.save();
  res.json(user);
});

module.exports = router;
