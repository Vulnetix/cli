const router = require('express').Router();
const PLUGINS = { csv: './plugins/csv', json: './plugins/json' };
const ALLOWED = ['csv', 'json'];

router.get('/a', (req, res) => {
  const p = require(PLUGINS[req.query.name]);
  res.json(p);
});

router.get('/b', (req, res) => {
  const name = req.query.name;
  if (!ALLOWED.includes(name)) return res.sendStatus(400);
  const p = require('./plugins/' + name);
  res.json(p);
});

router.get('/c', (req, res) => {
  const pkg = require('./package.json');
  const cfg = require(`./config/${process.env.NODE_ENV}.json`);
  res.json({ pkg, cfg });
});
// const x = require(req.query.name);
module.exports = router;
