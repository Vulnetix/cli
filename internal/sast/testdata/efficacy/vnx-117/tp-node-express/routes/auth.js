const express = require('express');
const logger = require('../lib/logger');
const router = express.Router();

router.post('/login', (req, res) => {
~>  console.log('login attempt for ' + req.body.username);
~>  logger.warn(`bad password for ${req.body.username}`);
~>  console.error('referer:', req.headers.referer);
  res.sendStatus(401);
});

module.exports = router;
