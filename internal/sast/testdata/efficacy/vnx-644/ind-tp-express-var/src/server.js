app.get('/tag', (req, res) => {
  const tag = req.query.tag;
  const body = render();
~>  res.set('X-Client-Tag', tag);
  res.send(body);
});
