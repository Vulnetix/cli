const express = require('express');

~>const debug = Boolean(process.env.APP_DEBUG);
~>const strictTls = process.env.STRICT_TLS || true;
~>const allowAnon = process.env.ALLOW_ANONYMOUS ?? false;

const router = express.Router();

router.get('/report', (req, res) => {
~>  const includeArchived = Boolean(req.query.includeArchived);
  res.json(buildReport(includeArchived, debug, strictTls, allowAnon));
});

module.exports = router;
