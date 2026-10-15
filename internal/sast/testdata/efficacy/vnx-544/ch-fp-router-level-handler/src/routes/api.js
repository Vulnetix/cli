const express = require('express');
const router = express.Router();

router.get('/items', (req, res) => res.json([]));

router.use(function (err, req, res, next) {
  req.log.error(err);
  res.status(500).json({ error: 'internal error' });
});

module.exports = router;
