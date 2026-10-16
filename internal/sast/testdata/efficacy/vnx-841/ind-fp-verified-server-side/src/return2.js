router.get('/checkout/return', async (req, res) => {
  const session = await stripe.checkout.sessions.retrieve(req.query.session_id);
  const checkout = await Checkout.findById(session.client_reference_id);
  if (session.payment_status === 'paid') {
    checkout.status = 'complete';
    await fulfil(checkout);
  }
  res.redirect('/thanks');
});
