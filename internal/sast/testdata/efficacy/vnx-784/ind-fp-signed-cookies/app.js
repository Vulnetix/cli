app.get('/admin', (req, res) => {
  if (req.signedCookies.role === 'admin') return res.send('ok');
  res.status(403).end();
});
