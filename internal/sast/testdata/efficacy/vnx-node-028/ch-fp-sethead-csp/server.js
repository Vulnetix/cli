const express = require('express');

const app = express();
app.use((req, res, next) => {
  res.set('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'");
  next();
});
app.get('/', (req, res) => res.render('index'));
