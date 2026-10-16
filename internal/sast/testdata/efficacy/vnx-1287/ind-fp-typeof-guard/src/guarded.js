app.get('/search', (req, res) => {
  const q = req.query.q;
  if (typeof q !== 'string') {
    return res.status(400).end();
  }
  const term = q.toLowerCase();
  res.json(index.lookup(term));
});
