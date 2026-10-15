router.get('/checkout/return', async (req, res) => {
  const session = await stripe.checkout.sessions.retrieve(req.query.session_id);
  const order = await Order.findOne({ sessionId: session.id });
  if (session.payment_status === 'paid') {
    order.status = 'paid';
    await order.save();
  }
  res.redirect('/orders');
});
