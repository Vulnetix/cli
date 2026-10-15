router.get('/items/:id', async (req, res) => {
  const item = await Item.get(req.params.id);
  if (!item) return res.status(404).send('missing');
  if (!item.visible) {
    res.status(403).json({ error: 'hidden' });
    return;
  }
  res.set('Cache-Control', 'no-store');
  res.json(item);
});
