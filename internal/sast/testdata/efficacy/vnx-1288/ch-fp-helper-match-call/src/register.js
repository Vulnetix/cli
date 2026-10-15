const express = require('express');
const router = express.Router();
const { passwordsMatch } = require('./validation');

router.post('/register', async (req, res) => {
  const { password, confirmPassword } = req.body;
  if (!passwordsMatch(password, confirmPassword)) {
    return res.status(422).json({ error: 'Passwords do not match' });
  }
  await createAccount(req.body.email, password);
  res.sendStatus(201);
});

module.exports = router;
