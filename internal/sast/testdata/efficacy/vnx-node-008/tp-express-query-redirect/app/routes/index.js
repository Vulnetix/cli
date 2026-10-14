module.exports = (app) => {
  app.get('/learn', (req, res) => {
~>    return res.redirect(req.query.url);
  });
  app.post('/done', (req, res) => {
~>    res.redirect(302, req.body.returnTo);
  });
};
