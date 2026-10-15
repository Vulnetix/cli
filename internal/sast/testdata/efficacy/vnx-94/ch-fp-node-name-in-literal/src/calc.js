const express = require('express');
const app = express();

app.get('/calc', (req, res) => {
  const expr = req.query.expr;
  const BOOT = 'globalThis.ready = true; /* expr evaluated later by the parser */';
  eval(BOOT);
  res.json({ result: safeMath.evaluate(expr) });
});
