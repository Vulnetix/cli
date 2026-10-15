router.post('/orders/:id/status', async (req, res) => {
  const order = await Order.findById(req.params.id);
~>  order.status = req.body.status;
  await order.save();
  res.json(order);
});

router.post('/orders/:id/confirm', async (req, res) => {
  const next = req.body.stage;
~>  await Order.updateOne({ _id: req.params.id }, { $set: { stage: next } });
  res.sendStatus(204);
});
