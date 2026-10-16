app.get('/find', (req, res) => {
~>  const re = new RegExp(req.query.pattern);
  res.json(items.filter(i => re.test(i.name)));
});
