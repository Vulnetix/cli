const express = require('express');
const User = require('../models/user');

const router = express.Router();

router.post('/register', async (req, res) => {
  const user = await User.create({
    email: req.body.email,
    password: req.body.password,
~>    role: req.body.role,
  });
  res.status(201).json({ id: user.id });
});

router.put('/:id', async (req, res) => {
  const { accountType } = req.body;
  const user = await User.findByPk(req.params.id);
~>  user.accountType = accountType;
  await user.save();
  res.json(user);
});

module.exports = router;
