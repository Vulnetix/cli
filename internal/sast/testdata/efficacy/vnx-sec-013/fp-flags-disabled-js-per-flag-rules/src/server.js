const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    // Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
    httpOnly: false,
    // Reported by VNX-614 (a cookie without Secure), not by this rule.
    secure: false,
    maxAge: 3600000,
  },
}));

app.post('/login', (req, res) => {
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  res.cookie('session', token, { httpOnly: false, maxAge: 900000 });
  res.redirect('/');
});
