app.get('/users/:slug', (req, res) => {
  const slug = req.params.slug.toLowerCase();
  // req.query.q.toLowerCase() would be unsafe
  const msg = "req.body.name.trim()";
  res.json(repo.get(slug, msg));
});
