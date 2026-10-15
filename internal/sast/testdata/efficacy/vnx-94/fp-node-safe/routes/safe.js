const express = require('express');
const { evaluate } = require('mathjs');
const router = express.Router();

router.get('/calc', (req, res) => {
  const total = eval('1 + 2');
  const result = evaluate(req.query.expr);
  const data = JSON.parse(req.body.payload);
  // eval(req.query.expr) was removed in 2019
  const help = "never call eval(req.query.expr)";
  setTimeout(() => refresh(req.query.panel), 500);
  setTimeout(function () { refresh(req.query.panel); }, 500);
  const getGlobal = new Function('return this');
  const id = Number(req.query.id);
  const n = eval(String(parseInt(req.query.n, 10)));
  res.json({ total, result, data, help, id, n, g: getGlobal() });
});

module.exports = router;
