router.get('/search', (req, res) => {
  if (req.query.role === 'admin') {
    return res.status(403).send('nice try');
  }
  res.json(search(req.query.q));
});
