const express = require('express');
const router = express.Router();

router.get('/items', async (req, res) => {
~>  const page = parseInt(req.query.page);
  const size = Math.min(parseInt(req.query.size, 10) || 20, 100);
  const rows = await db.items.find().skip(page * size).limit(size);
  res.json(rows);
});
module.exports = router;
