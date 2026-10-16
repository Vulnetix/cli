app.get('/a', (req, res) => {
  if (req.session.role === 'admin') return res.render('admin');
  if (req.signedCookies.admin) return res.render('admin');
  if (req.user && req.user.isAdmin) return res.render('admin');
  res.sendStatus(403);
});
