const express = require('express');
const router = express.Router();

router.post('/users/:id/ban', async (req, res) => {
  const { isAdmin } = req.body;
~>  if (isAdmin) {
    await users.ban(req.params.id);
    return res.sendStatus(204);
  }
  res.sendStatus(403);
});
