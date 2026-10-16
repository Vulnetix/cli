const Handlebars = require('handlebars');

app.post('/layout', (req, res) => {
~>  const fn = Handlebars.compile(req.body.layout);
  res.send(fn({ title: 'Report' }));
});
