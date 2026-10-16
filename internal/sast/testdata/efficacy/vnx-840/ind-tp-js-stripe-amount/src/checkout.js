router.post('/pay', async (req, res) => {
~>  const intent = await stripe.paymentIntents.create({ amount: req.body.amount, currency: 'usd' });
  res.json({ secret: intent.client_secret });
});
