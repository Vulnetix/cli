const express = require('express');
const router = express.Router();

router.get('/items', (req, res) => {
  const limit = parseInt(req.query.limit, 10);
  const isAdmin = req.query.admin === 'true';
  const n = Number(req.query.n);
  const total = parseInt('42');
  const width = parseInt(config.width);
  // parseInt(req.query.limit) without a radix is risky
  const ok = Boolean(user);
  res.json({ limit, isAdmin, n, total, width, ok });
});

module.exports = router;
