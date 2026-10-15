router.get('/range', (req, res) => {
  const parts = req.query.range.split('-');
  if (parts.length < 2) {
    return res.status(400).end();
  }
  res.json({ start: parts[0], end: parts[1] });
});
