const express = require('express');
const app = express();
const MAX = 4096;

app.get('/pad', (req, res) => {
  const size = Math.min(Number(req.query.size) || 0, MAX);
  const buf = Buffer.alloc(size);
  res.send(buf);
});
