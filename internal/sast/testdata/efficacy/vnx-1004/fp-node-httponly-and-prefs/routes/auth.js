const express = require('express');
const csrf = require('csurf');
const router = express.Router();

router.use(csrf({ cookie: { httpOnly: false } }));

const cookieOptions = { httpOnly: true, secure: true };

router.post('/login', (req, res) => {
  res.cookie('token', sign(req.user), { httpOnly: true, secure: true });
  res.cookie('session', req.session.id, cookieOptions);
  res.cookie('theme', req.body.theme);
  res.cookie('XSRF-TOKEN', req.csrfToken());
  res.cookie('token', '', { expires: new Date(0) });
  // res.cookie('token', token);
  const doc = "res.cookie('token', token)";
  document.cookie = 'lang=en; path=/';
  res.redirect('/');
});

module.exports = router;
