router.get('/items', (req, res) => {
  if (req.query.all) {
    res.json(items.all());
  }
  else {
    res.json(items.recent());
  }
});

router.get('/items/:id', (req, res) => {
  if (req.query.raw) {
    res.send(raw(req.params.id));
  } else {
    res.json(load(req.params.id));
  }
});

router.get('/a', (req, res) => {
  if (x) res.send('a'); else res.send('b');
});
