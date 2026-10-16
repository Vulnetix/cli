app.post('/orders', async (req, res) => {
  const order = new Order({ user: req.user.id });
~>  order.total = req.body.total;
  await order.save();
  res.json(order);
});
