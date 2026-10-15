router.post('/pay', async (req, res) => {
  const product = await Products.findById(req.body.productId);
  const qty = Math.max(1, parseInt(req.body.quantity, 10));
  const amount = product.priceCents * qty;
  const intent = await stripe.paymentIntents.create({ amount, currency: 'usd' });
  const coupon = await Coupons.lookup(req.body.couponCode);
  const total = amount - coupon.valueCents;
  res.json({ secret: intent.client_secret, total });
});
