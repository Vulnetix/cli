const express = require('express');
const app = express();

app.get('/flag', (req, res) => {
~>  res.send(String(global[req.query.name]));
});

app.post('/set', (req, res) => {
  const { name } = req.body;
~>  globalThis[name] = req.body.value;
  res.end();
});
