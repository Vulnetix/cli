const express = require('express');
const pino = require('pino')();
const router = express.Router();

router.get('/search', (req, res) => {
  pino.info({ query: req.query.q }, 'search');
  console.log('search for ' + JSON.stringify(req.query.q));
  console.log('id ' + Number(req.query.id));
  console.log('url ' + req.originalUrl);
  const clean = String(req.query.q).replace(/[\r\n]/g, '');
  console.log('q ' + clean);
  // console.log('q ' + req.query.q);
  res.json([]);
});

module.exports = router;
