router.get('/orders/:id', async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, owner: req.user.id });
  if (!order) return res.status(404).end();
  res.json(order);
});

router.get('/docs/:id', async (req, res) => {
  const doc = await Doc.findByPk(req.params.id);
  if (doc.ownerId !== req.user.id) {
    return res.status(403).end();
  }
  res.json(doc);
});
