const express = require('express');
const router = express.Router();
const items = [];

router.get('/items/:index', (req, res) => {
  const i = parseInt(req.params.index, 10);
~>  res.json(items[i]);
});

router.get('/rows', (req, res) => {
  const offset = Number(req.query.offset);
~>  const row = table.rows[offset];
  res.json(row);
});

module.exports = router;
