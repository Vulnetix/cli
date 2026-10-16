const express = require('express');
const router = express.Router();

router.post('/admin/purge', (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).end();
  }
  if (!req.session.isAdmin) {
    return res.status(403).end();
  }
  if (req.signedCookies.role !== 'admin') {
    return res.status(403).end();
  }
  res.json({ purged: true });
});

module.exports = router;
