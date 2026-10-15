app.get('/api/profile', (req, res) => {
  if (req.query.callback === undefined) {
    res.json(profile);
  } else {
    res.jsonp(profile);
  }
});
