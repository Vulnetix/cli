const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

router.post('/login', loginLimiter, async (req, res) => {
  res.json({ ok: true });
});
module.exports = router;
