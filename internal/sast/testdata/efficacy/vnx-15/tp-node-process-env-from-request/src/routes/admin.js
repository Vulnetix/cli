const express = require('express');
const router = express.Router();

router.post('/env', (req, res) => {
~>  process.env[req.body.key] = req.body.value;
  res.sendStatus(204);
});

router.get('/mode', (req, res) => {
~>  process.env.NODE_ENV = req.query.env;
  res.send('ok');
});

router.put('/feature/:flag', (req, res) => {
  const flag = req.params.flag;
~>  process.env.FEATURE_FLAG = flag;
~>  Object.assign(process.env, req.body.overrides);
  res.send('ok');
});

module.exports = router;
