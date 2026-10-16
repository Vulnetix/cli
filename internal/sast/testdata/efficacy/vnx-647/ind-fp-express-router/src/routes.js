router.get('/admin', requireAdmin, (req, res) => res.render('admin'));
app.use((req, res, next) => {
  if (req.path.startsWith('/static')) {
    res.set('Cache-Control', 'public, max-age=3600');
  }
  if (req.path === '/health') return res.send('ok');
  next();
});
