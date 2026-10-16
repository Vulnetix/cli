const express = require('express');
const session = require('express-session');
const router = express.Router();

router.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
~>    httpOnly: false,
  },
}));

router.post('/login', (req, res) => {
  const token = sign(req.user);
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  res.cookie('token', token);
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  res.cookie("sessionId", req.session.id, { secure: true, sameSite: 'lax' });
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  res.cookie(
    'refresh_token',
    token,
    { maxAge: 86400000 }
  );
  res.redirect('/');
});

module.exports = router;
