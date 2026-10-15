const express = require('express');
const User = require('../models/user');

const router = express.Router();

router.post('/session', async (req, res) => {
  const { email, passwordHash } = req.body;
  const user = await User.findOne({ email });
~>  if (!user || user.passwordHash !== passwordHash) {
    return res.status(401).end();
  }
  req.session.userId = user.id;
  return res.json({ ok: true });
});

module.exports = router;
