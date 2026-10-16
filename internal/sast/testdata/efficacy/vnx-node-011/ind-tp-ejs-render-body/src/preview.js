const ejs = require('ejs');

app.post('/preview', (req, res) => {
~>  const out = ejs.render(req.body.template, { user: req.user });
  res.send(out);
});
