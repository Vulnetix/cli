const express = require('express');

const router = express.Router();
const MAX_ROWS = 500;

router.get('/rows', (req, res) => {
  const count = Math.min(parseInt(req.query.count, 10) || 0, MAX_ROWS);
  const rows = [];
  for (let i = 0; i < count; i++) {
    rows.push({ i });
  }
  res.json(rows);
});

module.exports = router;
