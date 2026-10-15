const express = require('express');
const app = express();

process.env.NODE_ENV = process.env.NODE_ENV || 'production';

app.get('/port', (req, res) => {
  const port = process.env.PORT || req.query.port;
  if (process.env.DEBUG === req.query.debug) {
    res.send(String(port));
  }
});
