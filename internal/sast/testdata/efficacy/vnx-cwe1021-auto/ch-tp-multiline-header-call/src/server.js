const express = require('express');
const app = express();

app.use((req, res, next) => {
  res.setHeader(
~>    'X-Frame-Options',
    'ALLOWALL'
  );
  next();
});

app.get('/widget', (req, res) => {
~>  res.set('X-Frame-Options', `ALLOW-FROM ${req.query.origin}`);
  res.render('widget');
});

module.exports = app;
