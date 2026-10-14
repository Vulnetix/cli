const express = require('express');
const router = express.Router();

router.get('/filter', (req, res) => {
~>  const re = new RegExp(req.query.pattern);
  res.json(items.filter((i) => re.test(i.name)));
});

router.post('/validate', (req, res) => {
~>  const ok = RegExp(req.body.rule, 'i').test(req.body.value);
  res.json({ ok });
});

router.get('/grep', (req, res) => {
~>  res.json(text.match(req.query.q) || []);
});

module.exports = router;
