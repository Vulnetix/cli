const express = require('express');
const logger = require('./logger');

const app = express();

// errorhandler() is only for development; we use our own handler instead.
app.use((err, req, res, next) => {
  logger.error({ err }, 'request failed');
  res.status(500).json({ error: 'internal error' });
});

module.exports = app;
