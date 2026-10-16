app.get('/id', (req, res) => {
  const ok = req.query.id.match(/^\d+$/);
  const cleaned = req.query.name.replace('-', ' ').split(',');
  const has = req.query.tags.includes('x');
  res.json({ ok, cleaned, has });
});
