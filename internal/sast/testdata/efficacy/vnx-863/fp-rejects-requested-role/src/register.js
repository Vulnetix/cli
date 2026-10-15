router.post('/register', (req, res) => {
  if (req.query.role === 'admin') {
    return res.status(403).json({ error: 'cannot self-assign admin' });
  }
  if (req.headers['x-role'] === 'admin') throw new Error('forbidden');
  res.json(createUser(req.body));
});
