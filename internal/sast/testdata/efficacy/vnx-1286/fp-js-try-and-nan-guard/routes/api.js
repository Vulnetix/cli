router.post('/import', (req, res) => {
  let doc;
  try {
    doc = JSON.parse(req.body.document);
  } catch (e) {
    return res.status(400).send('invalid JSON');
  }
  res.json(doc);
});

router.get('/page', (req, res) => {
  const page = parseInt(req.query.page, 10);
  if (Number.isNaN(page) || page < 1) {
    return res.status(400).end();
  }
  const size = parseInt(req.query.size, 10) || 20;
  res.json({ page, size });
});
