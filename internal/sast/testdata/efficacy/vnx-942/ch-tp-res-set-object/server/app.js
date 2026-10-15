const express = require('express');
const app = express();

app.use((req, res, next) => {
~>  res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' });
  next();
});

app.get('/api/me', (req, res) => {
~>  res.header("Access-Control-Allow-Origin", req.headers.origin);
  res.header("Access-Control-Allow-Credentials", "true");
  res.json(req.user);
});
