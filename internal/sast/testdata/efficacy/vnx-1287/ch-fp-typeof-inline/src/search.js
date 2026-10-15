const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q.toLowerCase() : '';
  const id = req.params.id.toLowerCase();
  const term = String(req.query.term || '').trim();
  const lang = (req.headers['accept-language'] || 'en').split(',')[0];
  res.json({ q, id, term, lang });
});
