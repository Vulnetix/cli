const Product = require('../models/product');

module.exports = async function placeOrder(req, res) {
  const product = await Product.findById(req.body.productId);
  if (req.body.price !== product.price) { return res.status(400).end(); }
  const order = { productId: product.id, price: product.price, quantity: req.body.quantity };
  res.json(order);
};
