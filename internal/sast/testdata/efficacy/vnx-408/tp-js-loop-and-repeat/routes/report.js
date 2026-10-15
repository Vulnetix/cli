const express = require('express');
const router = express.Router();

router.get('/report', (req, res) => {
  const count = parseInt(req.query.count, 10);
  const rows = [];
~>  for (let i = 0; i < count; i++) {
    rows.push(buildRow(i));
  }
~>  res.send('-'.repeat(req.query.width));
});

router.post('/grid', (req, res) => {
  const { size } = req.body;
~>  const grid = new Array(size).fill(0);
~>  const cells = Array.from({ length: req.body.cells }, () => 0);
  res.json({ grid, cells });
});

module.exports = router;
