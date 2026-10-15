router.get('/report', (req, res) => {
  const count = Math.min(parseInt(req.query.count, 10), 100);
  for (let i = 0; i < count; i++) {
    rows.push(buildRow(i));
  }
  const width = Number(req.query.width);
  if (width > 80) return res.status(400).end();
  res.send('-'.repeat(width));
  for (let i = 0; i < req.body.items.length; i++) {
    handle(req.body.items[i]);
  }
  const hash = await bcrypt.hash(req.body.password, 12);
});
