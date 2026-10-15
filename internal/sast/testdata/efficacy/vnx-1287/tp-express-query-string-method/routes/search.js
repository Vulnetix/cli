const express = require('express');
const router = express.Router();

router.get('/search', (req, res) => {
~>  const term = req.query.q.toLowerCase();
~>  if (req.query.name.length > 32) {
    return res.status(400).end();
  }
~>  const tags = req.body.tags.split(',');
  res.json({ term, tags });
});

module.exports = router;
