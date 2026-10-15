const crypto = require('crypto');
const express = require('express');
const router = express.Router();
const store = new Map();

router.get('/captcha', (req, res) => {
  const a = crypto.randomInt(1, 10);
  const b = crypto.randomInt(1, 10);
  const answer = a + b;
  const captchaId = crypto.randomUUID();
  store.set(captchaId, answer);
~>  res.json({ captchaId, question: `${a} + ${b} = ?`, answer });
});

module.exports = router;
