const express = require('express');
const router = express.Router();

router.post('/contact', async (req, res) => {
  const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    body: new URLSearchParams({ secret: process.env.RECAPTCHA_SECRET, response: req.body.token }),
  });
~>  const { success } = await resp.json();
  if (!success) {
    return res.status(403).json({ success: false });
  }
  res.json({ success: true });
});

router.post('/comment', async (req, res) => {
  const data = await verifyToken(req.body.token, 'https://www.google.com/recaptcha/api/siteverify');
~>  if (data.success) {
    return res.json({ ok: true });
  }
  res.status(403).end();
});

module.exports = router;
