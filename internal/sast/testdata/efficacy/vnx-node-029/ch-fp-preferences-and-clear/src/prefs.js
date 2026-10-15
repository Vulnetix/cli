app.get('/theme/:t', (req, res) => {
  res.cookie('theme', req.params.t);
  res.cookie('locale', req.acceptsLanguages()[0], { maxAge: 86400000 });
  res.clearCookie('session');
  res.cookie('XSRF-TOKEN', req.csrfToken());
  res.end();
});
