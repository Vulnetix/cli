router.get('/users/:id', async (req, res) => {
  const user = await db.findUser(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'not found' });
  }
  res.json(user);
});

router.post('/login', function (req, res) {
  if (!req.body.password) {
    res.redirect('/login?error=1');
    return;
  }
  res.render('home', { user: req.user });
});

router.get('/x', (req, res) => {
  if (!req.query.q) return res.status(400).send('q required');
  res.send(search(req.query.q));
});
