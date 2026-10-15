const express = require('express');
const router = express.Router();

router.post('/reset', async (req, res) => {
~>  const r = Math.floor(Math.random() * 1e6);
  const user = await Users.find(req.body.email);
  user.resetCode = r;
  await user.save();
~>  res.cookie('sid', Math.random().toString(36).slice(2), { httpOnly: true });
  res.sendStatus(204);
});

module.exports = router;
