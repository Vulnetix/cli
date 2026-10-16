const express = require('express');

const router = express.Router();

router.use((req, res, next) => {
  // A decision on a privilege cookie: VNX-784 reports it.
  if (req.cookies.admin === '1') return next();
  res.status(403).end();
});

module.exports = router;
