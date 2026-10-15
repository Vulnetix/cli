router.get('/tags', (req, res) => {
  const tags = req.query.tags.split(',').map((t) => t.trim());
  const last = req.query.path.split('/').pop();
  res.json({ tags, last });
});
