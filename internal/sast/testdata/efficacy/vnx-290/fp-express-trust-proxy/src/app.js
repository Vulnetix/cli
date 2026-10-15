const express = require('express');
const app = express();
app.set('trust proxy', 'loopback');

app.use((req, res, next) => {
  if (req.ip === '127.0.0.1') {
    req.isInternal = true;
  }
  res.setHeader('X-Forwarded-For', req.ip);
  const fwd = req.headers['x-forwarded-for'];
  if (fwd === undefined) {
    console.log('direct');
  }
  next();
});
