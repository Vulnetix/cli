const express = require('express');
const { refresh, poll } = require('./dashboard');

const app = express();

app.get('/panels/refresh', (req, res) => {
  const panel = req.query.panel;
  setTimeout(() => refresh(panel), 500);
  setInterval(poll, 10000);
  setTimeout(function () { refresh(req.query.panel); }, 1000);
  res.sendStatus(202);
});

// Never do: eval(req.query.panel)
module.exports = app;
