router.get('/admin', async (req, res) => {
  if (req.session.role === 'admin') {
    return res.render('admin');
  }
  if (req.signedCookies.admin === 'true') {
    return res.render('admin');
  }
  const user = await User.findById(req.session.userId);
  if (user.role === 'admin') {
    return res.render('admin');
  }
  res.status(403).end();
});
