app.use((req, res, next) => {
  if (req.headers['content-type'] === 'application/json') {
    req.isJson = true;
  }
  const token = req.cookies.session;
  if (token) {
    req.user = verify(token);
  }
  if (req.headers.authorization) {
    req.bearer = req.headers.authorization.slice(7);
  }
  if (req.query.page === 'admin') {
    res.locals.tab = 'admin';
  }
  next();
});
