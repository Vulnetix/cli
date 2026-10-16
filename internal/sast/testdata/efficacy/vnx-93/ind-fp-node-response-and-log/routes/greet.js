const express = require('express');
const logger = require('../lib/logger');

const router = express.Router();

router.get('/greet', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.write('Name: ' + req.query.name + '\r\n');
  res.write('Visited: ' + new Date().toISOString() + '\r\n');
  logger.info('Subject: greeting for ' + req.query.name);
  res.end();
});

module.exports = router;
