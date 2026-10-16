module.exports = function donate(req, res) {
  const amount = Number(req.body.amount);
  const quantity = parseInt(req.body.quantity, 10);
  // price: req.body.price would let the client pick it
  res.json({ amount, quantity });
};
