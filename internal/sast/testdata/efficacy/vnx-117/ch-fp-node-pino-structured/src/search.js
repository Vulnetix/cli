const express = require('express');
const pino = require('pino');

const log = pino();
const router = express.Router();

router.get('/search', (req, res) => {
  log.info({ query: req.query.q, ip: req.ip }, 'search');
  log.info('search %j', req.query.q);
  log.info('search ' + JSON.stringify(req.query.q));
  log.info(`page ${Number(req.query.page)}`);
  res.json([]);
});

module.exports = router;
