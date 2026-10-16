app.get('/profile', (req, res) => {
  res.render('profile', { name: req.query.name, bio: req.query.bio });
});
