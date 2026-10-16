router.get('/checkout/return', async (req, res) => {
  const checkout = await Checkout.findById(req.query.id);
~>  if (req.query.paid === 'true') {
    checkout.status = 'complete';
    await fulfil(checkout);
  }
  res.redirect('/thanks');
});
