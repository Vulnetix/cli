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
~>  res.cookie('token', token);
~>  res.cookie("sessionId", req.session.id, { secure: true, sameSite: 'lax' });
~>  res.cookie(
    'refresh_token',
    token,
    { maxAge: 86400000 }
  );
  res.redirect('/');
});

module.exports = router;
