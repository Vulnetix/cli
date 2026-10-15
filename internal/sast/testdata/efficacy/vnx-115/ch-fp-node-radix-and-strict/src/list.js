const express = require('express');
const router = express.Router();

const DEFAULT_PAGE = '1';

router.get('/list', (req, res) => {
  const page = parseInt(req.query.page, 10);
  const size = Number(req.query.size);
  const admin = req.query.admin === 'true';
  const first = parseInt(DEFAULT_PAGE);
  const owner = Boolean(req.user && req.user.isOwner);
  // parseInt(req.query.x) without a radix reads "0x1f" as hex
  res.json({ page, size, admin, first, owner });
});

module.exports = router;
