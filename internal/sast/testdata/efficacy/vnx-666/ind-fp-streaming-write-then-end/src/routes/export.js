const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/export.csv', async (req, res) => {
  res.setHeader('Content-Type', 'text/csv');
  const rows = await db.query('SELECT id, name FROM customers');
  res.write('id,name\n');
  for (const row of rows) {
    res.write(`${row.id},${row.name}\n`);
  }
  res.end();
});

router.get('/later', (req, res) => {
  setTimeout(() => {
    res.json({ done: true });
  }, 10);
  // res.json({ queued: true }) would be wrong here, so we do not do it
});

module.exports = router;
