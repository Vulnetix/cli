function escapeRegExp(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

app.get('/find', (req, res) => {
  const re = new RegExp(escapeRegExp(req.query.q), 'i');
  res.json(items.filter(i => re.test(i.name)));
});
