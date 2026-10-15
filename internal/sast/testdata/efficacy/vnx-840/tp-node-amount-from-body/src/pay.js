router.post('/pay', async (req, res) => {
~>  const intent = await stripe.paymentIntents.create({ amount: req.body.amount, currency: 'usd' });
  res.json({ secret: intent.client_secret });
});

router.post('/checkout', async (req, res) => {
  const price = Number(req.body.price);
  const session = await stripe.checkout.sessions.create({
    line_items: [{
      price_data: {
        currency: 'usd',
~>        unit_amount: price,
        product_data: { name: req.body.name },
      },
      quantity: 1,
    }],
    mode: 'payment',
  });
  res.redirect(session.url);
});
