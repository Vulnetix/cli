router.post('/cart', async (req, res) => {
  const { productId, quantity } = req.body;
~>  await CartItem.create({ productId, quantity });
  res.sendStatus(201);
});

router.post('/redeem', async (req, res) => {
  const { points } = req.body;
~>  await Member.updateOne({ _id: req.user.id }, { $inc: { points: -points } });
  res.sendStatus(200);
});
