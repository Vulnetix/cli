router.get('/panel', (req, res) => {
~>  if (req.user.isAdmin = true) {
    return res.render('panel');
  }
  res.sendStatus(403);
});
