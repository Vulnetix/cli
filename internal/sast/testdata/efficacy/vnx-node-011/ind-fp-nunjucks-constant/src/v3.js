const nunjucks = require('nunjucks');

app.get('/greet', (req, res) => {
  res.send(nunjucks.renderString('Hello {{ name }}', { name: req.query.name }));
});
