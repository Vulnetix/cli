router.get('/pair', (req, res) => {
  res.write(req.query.a + ',' + req.query.b);
  res.end();
});
