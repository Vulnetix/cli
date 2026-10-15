const express = require('express');
const router = express.Router();

router.get('/rows', (req, res) => {
~>  const rows = Array.from({ length: Number(req.query.count) }, (_, i) => ({ i }));
  res.json(rows);
});

module.exports = router;
