const express = require('express');
const router = express.Router();
const { User } = require('../models');

router.post('/forgot', async (req, res) => {
  const user = await User.findOne({ where: { email: req.body.email } });
  if (user) {
~>    const resetToken = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
    await user.update({ resetToken, resetExpires: Date.now() + 3600000 });
  }
  res.status(202).end();
});

module.exports = router;
