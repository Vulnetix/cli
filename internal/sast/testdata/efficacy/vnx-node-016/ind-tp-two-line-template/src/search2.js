app.get('/s', (req, res) => {
  const term = req.query.search;
~>  const re = new RegExp(term, 'gi');
  res.json(lines.filter(l => re.test(l)));
});
app.get('/n/:name', (req, res) => {
~>  const pattern = new RegExp(`^${req.params.name}$`, 'i');
  res.json(names.filter(n => pattern.test(n)));
});
