router.get('/preview', (req, res) => {
  const quantity = req.query.quantity;
  res.render('preview', { label: 'Qty: ' + quantity });
});
// stock += req.body.quantity would be wrong without a check
const msg = "item.stock -= req.body.quantity";
