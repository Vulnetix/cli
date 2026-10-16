const express = require('express');
const { findUserById } = require('../services/users');

const router = express.Router();

router.get('/users/:id', async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) {
~>    res.status(404).json({ error: 'user not found' });
  }
  res.json({ id: user.id, email: user.email });
});

module.exports = router;
