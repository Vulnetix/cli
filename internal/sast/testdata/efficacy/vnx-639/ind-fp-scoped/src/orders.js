router.get('/orders/:id', async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, owner: req.user.id });
  if (!order) return res.status(404).end();
  res.json(order);
});

router.get('/me', async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json(user);
});
