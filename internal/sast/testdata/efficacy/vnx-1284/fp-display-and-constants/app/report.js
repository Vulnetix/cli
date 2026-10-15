function show(req, res) {
  const quantity = req.query.quantity;
  res.render('item', { quantity, label: 'amount * price' });
  const count = parseInt(req.query.count, 10);
  res.json({ count });
}

module.exports = { show };
