const express = require('express');
const router = express.Router();

router.post('/signup', async (req, res) => {
  const { username, password } = req.body;
~>  if (username === 'admin' || username === 'root') {
    return res.status(400).json({ error: 'name not allowed' });
  }
  await createUser(username, password);
  res.status(201).end();
});

module.exports = router;
