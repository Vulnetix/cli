const nunjucks = require('nunjucks');

app.get('/hello', (req, res) => {
  const name = req.query.name;
  const tpl = 'Hello ' + name + '!';
~>  res.send(nunjucks.renderString(tpl, {}));
});
