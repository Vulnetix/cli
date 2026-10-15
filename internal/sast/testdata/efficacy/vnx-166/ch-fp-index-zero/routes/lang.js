router.get('/lang', (req, res) => {
  const lang = req.headers['accept-language'].split(',')[0];
  res.send(lang);
});
