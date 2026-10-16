app.post('/users', (req, res) => {
  if (req.body.role === 'admin' && !req.user.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json(create(req.body));
});
