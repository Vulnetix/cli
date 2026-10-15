const express = require('express');
const router = express.Router();

// CSV rows end in CRLF (RFC 4180); the body is not a header block.
router.get('/export.csv', async (req, res) => {
  const rows = await db.orders(req.user.id);
  res.type('text/csv');
  res.write('id,total\r\n');
  for (const row of rows) {
    res.write(`${row.id},${row.total}\r\n`);
  }
  res.end(`# generated for ${req.query.label}\r\n`);
});

module.exports = router;
