const express = require('express');
const app = express();

app.use((req, res, next) => {
~>  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST');
  next();
});

app.get('/me', (req, res) => {
~>  res.header("Access-Control-Allow-Origin", "*");
  res.json(req.user);
});
