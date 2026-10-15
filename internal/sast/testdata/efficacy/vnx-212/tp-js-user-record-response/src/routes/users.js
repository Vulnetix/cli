const express = require('express');
const User = require('../models/user');
const router = express.Router();

router.get('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).end();
~>  res.json(user);
});

router.get('/me', async (req, res) => {
  const account = await db.Account.findByPk(req.session.accountId);
~>  return res.status(200).send({ account });
});

router.get('/admins', async (req, res) => {
  const admins = await User.find({ role: 'admin' });
~>  res.json({ count: admins.length, items: admins });
});

module.exports = router;
