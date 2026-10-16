'use strict';

const express = require('express');
const app = express();

app.get('/hello', (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1><p>Welcome back.</p>`);
});

module.exports = app;
