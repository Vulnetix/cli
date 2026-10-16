const express = require('express');
const router = express.Router();

router.get('/items', (req, res) => {
  const limit = parseInt(req.query.limit);
~>  const isAdmin = Boolean(req.query.admin);
~>  const offset = Number.parseInt(
    req.query.offset
  );
~>  if (!!req.query.confirm) {
    res.json({ limit, isAdmin, offset });
  }
});

module.exports = router;
