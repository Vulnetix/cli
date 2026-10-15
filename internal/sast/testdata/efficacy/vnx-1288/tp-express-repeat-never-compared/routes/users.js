const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

router.post('/users', async (req, res) => {
  if (!req.body.email || !req.body.password) {
    return res.status(400).end();
  }
~>  req.body.passwordRepeat = req.body.passwordRepeat.trim();
  const hash = await bcrypt.hash(req.body.password, 12);
  await Users.create({ email: req.body.email, hash });
  res.status(201).end();
});

module.exports = router;
