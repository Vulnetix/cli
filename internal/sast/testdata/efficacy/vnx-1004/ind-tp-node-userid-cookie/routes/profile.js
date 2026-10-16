const express = require('express');
const router = express.Router();

router.post('/signin', async (req, res) => {
  const user = await verify(req.body.email, req.body.password);
  if (!user) return res.sendStatus(401);
~>  res.cookie('user_id', user.id, { maxAge: 86400000, secure: true });
  res.json({ ok: true });
});

module.exports = router;
