const express = require('express');
const app = express();

app.get('/list', (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const size = Number(req.query.size) ?? 20;
  const copy = JSON.parse(JSON.stringify(req.body));
  res.json({ page, size, copy });
});

app.get('/offset', (req, res) => {
  const offset = parseInt(req.query.offset, 10);
  if (Number.isNaN(offset)) {
    return res.status(400).end();
  }
  res.json({ offset });
});
