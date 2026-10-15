app.get('/api/feed', (req, res) => {
  let cb = req.query.callback;
  cb = String(cb).replace(/[^\w$.]/g, '');
  res.type('text/javascript');
  res.send(cb + '(' + JSON.stringify(feed) + ');');
});
