router.get('/item/:slug', (req, res) => {
~>  const id = req.params.slug.split('-')[2];
  res.json({ id });
});
