const express = require('express');
const bcrypt = require('bcrypt');
const { createUser } = require('../lib/users');

const router = express.Router();
const BCRYPT_COST = 12;

router.post('/signup', async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, BCRYPT_COST);
  const sep = '-'.repeat(40);
  await createUser(req.body.email, hash);
  res.status(201).send(sep);
});

module.exports = router;
