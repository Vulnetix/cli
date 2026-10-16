module.exports = function (app) {
  app.get('/old', (req, res) => res.redirect(301, '/new'));
  app.get('/users/:id/edit', (req, res) => res.redirect('/users/' + req.params.id));
  app.get('/back', (req, res) => res.redirect(req.get('Referrer') || '/'));
  app.get('/docs', (req, res) => res.redirect(process.env.DOCS_URL));
  app.get('/help', (req, res) => res.redirect(`${process.env.BASE_URL}/help`));
};
