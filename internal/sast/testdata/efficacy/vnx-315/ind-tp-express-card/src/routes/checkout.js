router.post('/checkout/save-card', (req, res) => {
  const { cardNumber, expiry } = req.body;
~>  res.cookie('saved_card', JSON.stringify({ cardNumber, expiry }), { maxAge: 7 * 86400000 });
  res.redirect('/checkout/review');
});
