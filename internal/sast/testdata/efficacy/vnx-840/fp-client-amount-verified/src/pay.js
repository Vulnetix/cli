router.post('/pay', async (req, res) => {
  const order = await Orders.findById(req.body.orderId);
  const amount = Number(req.body.amount);
  if (amount !== order.totalCents) {
    return res.status(400).json({ error: 'amount mismatch' });
  }
  const intent = await stripe.paymentIntents.create({ amount: order.totalCents, currency: 'usd' });
  res.json({ secret: intent.client_secret });
});
