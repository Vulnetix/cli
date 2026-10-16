'use strict';

const express = require('express');
const app = express();

// Never do process.env[req.body.key] = req.body.value; it changes the
// environment for every request.
process.env.NODE_ENV = process.env.NODE_ENV || 'production';

app.get('/health', (req, res) => {
  const verbose = req.query.verbose === '1';
  res.json({ env: process.env.NODE_ENV, verbose });
});

const help = 'set process.env.LOG_LEVEL from req.query.level';
module.exports = { app, help };
