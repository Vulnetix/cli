const pug = require('pug');

app.get('/page', (req, res) => {
  const html = pug.renderFile('views/page.pug', { q: req.query.q });
  res.send(html);
});
