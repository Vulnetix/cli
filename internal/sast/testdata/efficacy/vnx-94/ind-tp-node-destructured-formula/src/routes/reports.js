const express = require('express');
const db = require('../db');

const router = express.Router();

router.post('/reports/custom-column', async (req, res) => {
  const { formula, label: title } = req.body;
  const rows = await db.orders.findAll({ limit: 500 });

~>  const compute = new Function('row', 'return (' + formula + ');');
  const values = rows.map((row) => ({ id: row.id, value: compute(row) }));

  res.json({ title, values });
});

module.exports = router;
