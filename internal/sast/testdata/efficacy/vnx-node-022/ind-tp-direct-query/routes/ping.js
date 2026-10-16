const shell = require('shelljs');
const express = require('express');
const app = express();
app.get('/ping', (req, res) => {
~>  const out = shell.exec('ping -c 1 ' + req.query.host);
  res.send(out.stdout);
});
