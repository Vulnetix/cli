const express = require('express');
const app = express();

app.get('/calc', (req, res) => {
~>  const out = eval(req.query.expr);
  res.send(String(out));
});
