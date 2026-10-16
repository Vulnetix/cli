const express = require('express');
const os = require('os');

const router = express.Router();

router.get('/healthz', (req, res) => {
  res.json({
    status: 'ok',
    host: os.hostname(),
    uptime: process.uptime(),
~>    env: process.env,
  });
});

module.exports = router;
