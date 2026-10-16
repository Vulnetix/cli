app.get('/find', (req, res) => {
  const name = String(req.query.name || '');
  res.json(repo.find(name.trim().toLowerCase()));
});
