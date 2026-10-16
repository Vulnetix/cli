app.get('/pick', (req, res) => {
  const users = cache.users;
  const hit = users.find(u => u.name === req.query.name);
  res.json(hit);
});
