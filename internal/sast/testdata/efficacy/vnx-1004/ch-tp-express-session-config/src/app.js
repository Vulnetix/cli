const express = require('express');
const session = require('express-session');

const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
~>  cookie: { secure: true, httpOnly: false, maxAge: 3600000 },
}));

app.post('/login', (req, res) => {
  const token = issueToken(req.body.user);
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  res.cookie('access_token', token, { secure: true, sameSite: 'strict' });
  res.json({ ok: true });
});

module.exports = app;
