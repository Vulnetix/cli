const express = require('express');
const router = express.Router();

router.get('/items/:id', (req, res) => {
~>  const filter = JSON.parse(req.params.id);
  res.json(db.find(filter));
});

router.get('/page/:n', (req, res) => {
~>  const n = parseInt(req.params.n, 10);
  res.json(db.page(n));
});

module.exports = router;
