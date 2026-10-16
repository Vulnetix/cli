router.post('/a', (req, res) => {
  if (req.user && req.user.role === 'admin') return ok(res);
  if (req.session.isAdmin) return ok(res);
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).end();
  if (req.body.isAdmin === undefined) return res.status(400).end();
  // if (req.body.isAdmin) { ... }
  res.status(403).end();
});
