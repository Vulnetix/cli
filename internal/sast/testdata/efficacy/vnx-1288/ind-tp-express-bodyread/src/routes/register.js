const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
~>  const repeat = req.body.passwordRepeat;
  const hash = await bcrypt.hash(password, 12);
  await users.insert({ email, hash });
  res.sendStatus(201);
});
module.exports = router;
