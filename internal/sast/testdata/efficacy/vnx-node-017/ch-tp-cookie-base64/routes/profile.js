const express = require('express');
const serialize = require('node-serialize');

const router = express.Router();

router.get('/profile', (req, res) => {
  const raw = Buffer.from(req.cookies.profile, 'base64').toString();
~>  const profile = serialize.unserialize(raw);
  res.send('Hello ' + profile.username);
});

module.exports = router;
