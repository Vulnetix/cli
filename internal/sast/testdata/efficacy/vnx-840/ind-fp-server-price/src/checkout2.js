router.post('/pay', async (req, res) => {
  const product = await Product.findById(req.body.productId);
  const qty = Number(req.body.quantity);
  const intent = await stripe.paymentIntents.create({
    amount: product.price_cents * qty,
    currency: 'usd',
    metadata: { coupon: req.body.coupon_code },
  });
  res.json({ secret: intent.client_secret });
});
