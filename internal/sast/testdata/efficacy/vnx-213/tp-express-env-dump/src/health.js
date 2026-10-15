const express = require('express');
const app = express();

app.get('/healthz', (req, res) => {
~>  res.json({ status: 'ok', env: process.env });
});

app.get('/debug/env', (req, res) => {
~>  res.send(JSON.stringify(process.env, null, 2));
});

app.get('/info', (req, res) => {
  const vars = { ...process.env };
~>  res.status(200).json(vars);
});

module.exports = app;
