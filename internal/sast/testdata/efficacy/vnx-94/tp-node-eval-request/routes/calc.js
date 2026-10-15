const express = require('express');
const router = express.Router();

router.get('/calc', (req, res) => {
~>  const result = eval(req.query.expr);
  res.send(String(result));
});

router.post('/formula', (req, res) => {
  const formula = req.body.formula;
  const wrapped = 'return (' + formula + ');';
~>  const out = eval(wrapped);
  res.json({ out });
});

router.get('/legacy', function (req, res) {
~>  res.send(String(window.eval(`${req.params.code}`)));
});

module.exports = router;
