router.get('/search', (req, res) => {
  const q = req.query.q;
  if (typeof q !== 'string') {
    return res.status(400).end();
  }
  const term = q.toLowerCase();
  const name = String(req.query.name).trim();
  const id = req.params.id.toLowerCase();
  const raw = req.body;
  res.json({ term, name, id, raw });
});
