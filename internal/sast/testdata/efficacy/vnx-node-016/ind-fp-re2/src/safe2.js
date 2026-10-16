const RE2 = require('re2');

app.get('/find', (req, res) => {
  const re = new RE2(req.query.pattern);
  res.json(items.filter(i => re.test(i.name)));
});
