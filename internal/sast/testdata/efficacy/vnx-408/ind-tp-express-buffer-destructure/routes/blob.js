const express = require('express');

const router = express.Router();

router.post('/blob/reserve', (req, res) => {
  const { size, fill } = req.body;
~>  const buf = Buffer.alloc(size, fill || 0);
  res.json({ reserved: buf.length });
});

module.exports = router;
