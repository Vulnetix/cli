const express = require('express');
const router = express.Router();

function localOnly(req, res, next) {
~>  if (req.connection.remoteAddress === '127.0.0.1') {
    return next();
  }
  res.status(403).end();
}

router.use(localOnly);
module.exports = router;
