const express = require('express');
const serialize = require('node-serialize');

const router = express.Router();

router.get('/profile', (req, res) => {
  if (!req.cookies.profile) {
    return res.redirect('/login');
  }
  const raw = Buffer.from(req.cookies.profile, 'base64').toString();
~>  const profile = serialize.unserialize(raw);
  res.render('profile', { name: profile.username });
});

router.post('/restore', (req, res) => {
~>  const state = serialize.unserialize(req.body.state);
  res.json({ restored: Object.keys(state).length });
});

module.exports = router;
