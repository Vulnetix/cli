const express = require('express');
const router = express.Router();

router.get('/items/:id', (req, res) => {
~>  const id = JSON.parse(req.params.id);
  res.json({ id });
});

router.post('/filter', (req, res) => {
  const raw = req.query.filter;
~>  const filter = JSON.parse(raw);
  res.json(filter);
});

module.exports = router;
