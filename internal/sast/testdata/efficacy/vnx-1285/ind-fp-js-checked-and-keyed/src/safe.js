router.get('/item/:index', (req, res) => {
  const i = parseInt(req.params.index, 10);
  if (!(i >= 0 && i < items.length)) return res.sendStatus(404);
  res.json(items[i]);
});

router.get('/user/:id', (req, res) => {
  res.json(users[req.params.id]);
});

const page = rows.slice(Number(req.query.offset), Number(req.query.offset) + 20);
// items[parseInt(req.query.index)] needs a bounds check
