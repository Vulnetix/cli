const ejs = require('ejs');
app.get('/greet', (req, res) => {
  const html = ejs.render('<p><%= name %></p>', { name: req.query.name });
  res.send(html);
});
app.get('/page', (req, res) => res.render('page', { q: req.query.q }));
