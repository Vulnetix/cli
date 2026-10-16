const express = require('express');
const { User } = require('../models');

const router = express.Router();

router.post('/users', async (req, res) => {
  const { email } = req.body;
  const user = await User.create({
    email,
~>    password: Buffer.from(req.body.password, 'utf8').toString('hex'),
  });
  res.status(201).json({ id: user.id });
});

module.exports = router;
