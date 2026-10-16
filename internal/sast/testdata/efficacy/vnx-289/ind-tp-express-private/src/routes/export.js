const express = require('express');
const router = express.Router();

router.use((req, res, next) => {
~>  if (req.originalUrl === '/api/private/export' && !req.user) {
    return res.sendStatus(401);
  }
  next();
});

router.get('/api/private/export', (req, res) => res.json(buildExport()));
module.exports = router;
