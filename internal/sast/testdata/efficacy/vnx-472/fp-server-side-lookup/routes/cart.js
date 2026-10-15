const { Product, Transfer } = require('../models');

async function addToCart(req, res) {
  const { productId, quantity } = req.body;
  const product = await Product.findByPk(productId);
  const total = product.price * quantity;
  if (req.body.price !== product.price) {
    return res.status(400).json({ error: 'price changed' });
  }
  res.json({ price: product.price, total });
}

async function transfer(req, res) {
  const amount = Number(req.body.amount);
  await Transfer.create({ from: req.user.id, to: req.body.to, amount });
  res.json({ ok: true });
}

async function quote(res) {
  const data = await fetch('/api/price').then((r) => r.json());
  return data.price;
}

module.exports = { addToCart, transfer, quote };
