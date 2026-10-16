const express = require('express');
const session = require('express-session');
const router = express.Router();

router.use(session({
  secret: process.env.SESSION_KEY,
  resave: false,
~>  cookie: { httpOnly: true, secure: false }
}));

router.post('/login', (req, res) => {
  const token = sign(req.body.user);
~>  res.cookie('token', token);
  res.json({ ok: true });
});

module.exports = router;
