const Handlebars = require('handlebars');
app.post('/preview', (req, res) => {
  const src = req.body.template;
~>  const fn = Handlebars.compile(src);
  res.send(fn({ user: 'demo' }));
});
