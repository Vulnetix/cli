const express = require('express');
const cors = require('cors');
const app = express();
const allowed = new Set(['https://app.example.com']);

app.use(cors({ origin: (origin, cb) => cb(null, allowed.has(origin)) }));
app.use('/pub', cors({ origin: 'https://www.example.com' }));

app.use((req, res, next) => {
  if (allowed.has(req.headers.origin)) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  }
  next();
});
