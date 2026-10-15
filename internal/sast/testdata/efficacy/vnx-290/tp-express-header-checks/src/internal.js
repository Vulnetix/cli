const express = require('express');
const router = express.Router();

router.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
~>  if (ip === '127.0.0.1' || ip === '::1') {
    req.isInternal = true;
  }
  next();
});

router.get('/debug', (req, res) => {
~>  if (!ALLOWED_IPS.includes(req.get('X-Client-IP'))) {
    return res.status(403).end();
  }
  res.json(debugInfo());
});

module.exports = router;
