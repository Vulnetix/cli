app.post('/prefs', (req, res) => {
  res.cookie('accessibilityMode', req.body.mode);
  res.cookie('authorFilter', req.query.author);
  res.cookie('lastVisit', new Date().toISOString());
  res.end();
});
