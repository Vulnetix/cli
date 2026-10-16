app.get('/grep', (req, res) => {
~>  res.json(text.match(req.query.q) || []);
});
