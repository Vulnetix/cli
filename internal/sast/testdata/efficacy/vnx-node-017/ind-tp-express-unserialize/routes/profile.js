const express = require('express');
const serialize = require('node-serialize');
const router = express.Router();

router.get('/profile', (req, res) => {
  const cookie = Buffer.from(req.cookies.profile, 'base64').toString();
~>  const obj = serialize.unserialize(cookie);
  res.send('Hello ' + obj.username);
});

module.exports = router;
