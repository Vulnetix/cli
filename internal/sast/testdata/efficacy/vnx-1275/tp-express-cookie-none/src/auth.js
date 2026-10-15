const express = require('express');
const router = express.Router();

router.post('/login', (req, res) => {
  const token = issue(req.body.user);
~>  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'none' });
~>  res.cookie("remember", token, {sameSite:"None"});
  res.json({ ok: true });
});

module.exports = router;
