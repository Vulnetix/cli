const express = require('express');
const app = express();

app.get('/pad', (req, res) => {
~>  const buf = Buffer.alloc(Number(req.query.size));
  res.send(buf);
});
