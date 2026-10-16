router.get('/panel', (req, res) => {
  if (req.user.role === 'admin') {
    return res.render('panel');
  }
  if (req.session.role === 'owner' && req.get('Authorization')) {
    return res.render('owner');
  }
  res.sendStatus(403);
});
