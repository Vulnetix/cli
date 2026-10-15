const fs = require('fs');
const express = require('express');
const router = express.Router();

router.post('/signup', (req, res) => {
~>  fs.appendFileSync('users.csv', req.body.name + ',' + req.body.email + '\n');
  res.send('ok');
});

module.exports = router;
