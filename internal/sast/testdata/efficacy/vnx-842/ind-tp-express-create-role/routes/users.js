const express = require('express');
const { User } = require('../models');
const router = express.Router();

router.post('/register', async (req, res) => {
  const user = await User.create({
    email: req.body.email,
    password: await hash(req.body.password),
~>    role: req.body.role,
  });
  res.status(201).json({ id: user.id });
});

module.exports = router;
