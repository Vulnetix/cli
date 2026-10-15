const sh = require('shelljs');
const express = require('express');

const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  const cmd = 'ping -c 1 ' + host;
~>  const out = sh.exec(cmd, { silent: true }).stdout;
  res.type('text').send(out);
});
