app.get('/f', async (req, res) => {
  const r = await fetch(req.query.url);
  res.sendStatus(r.status);
});
