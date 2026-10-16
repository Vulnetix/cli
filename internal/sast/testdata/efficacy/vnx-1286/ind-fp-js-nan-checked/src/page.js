router.get('/list', (req, res) => {
  const page = Number.parseInt(req.params.page, 10);
  if (Number.isNaN(page) || page < 1) {
    return res.status(400).end();
  }
  res.json(db.page(page));
});

router.get('/safe/:body', (req, res) => {
  let doc;
  try {
    doc = JSON.parse(req.params.body);
  } catch (e) {
    return res.status(400).json({ error: 'bad json' });
  }
  res.json(doc);
});
