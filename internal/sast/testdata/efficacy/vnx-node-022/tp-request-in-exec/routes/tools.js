const express = require('express');
const shell = require('shelljs');

const router = express.Router();

router.get('/ping', (req, res) => {
~>  const out = shell.exec('ping -c 1 ' + req.query.host, { silent: true });
  res.send(out.stdout);
});

router.post('/lookup', (req, res) => {
~>  const result = shell.exec(`nslookup ${req.body.domain}`, { silent: true }).stdout;
  res.send(result);
});

module.exports = router;
