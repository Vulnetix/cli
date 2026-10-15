const Product = require('../models/product');

async function addToCart(req, res) {
  const qty = parseInt(req.body.quantity, 10);
  const product = await Product.findById(req.body.productId);
  const fee = req.query.fee;
  console.log('requested fee', fee);
  req.session.cart.total = product.price * qty;
  res.json({ total: req.session.cart.total });
}

module.exports = { addToCart };
