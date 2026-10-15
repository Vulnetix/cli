const express = require('express');
const router = express.Router();

router.get('/export', async (req, res) => {
  const fields = (req.query.fields || 'id,name').split(',');
  const ids = req.body.ids.split(',');
  const rows = await db.select(fields).whereIn('id', ids);
  res.attachment('report.csv');
  res.type('text/csv');
  res.send(rows.map((r) => fields.map((f) => JSON.stringify(r[f])).join(',')).join('\n'));
});

module.exports = router;
