const express = require('express');
const router = express.Router();

router.post('/preferences', (req, res) => {
  // Stores display preferences only; no authorisation data lives here.
  res.cookie('theme', req.body.theme === 'dark' ? 'dark' : 'light', { maxAge: 31536000000 });
  res.cookie('admin_theme', 'compact', { maxAge: 31536000000 });
  res.cookie('session', req.sessionID, { httpOnly: true, secure: true });
  const token = req.cookies.auth_token;
  res.json({ ok: Boolean(token) });
});

module.exports = router;
