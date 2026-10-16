const express = require('express');
const app = express();

app.get('/search', (req, res) => {
~>  const term = req.query.q.toLowerCase();
  res.json(index.lookup(term));
});
