const express = require('express');
const router = express.Router();
const Product = require('../models/product');

router.get('/products', async (req, res) => {
  const maxPrice = Number(req.query.maxPrice) || Infinity;
  const sortBy = req.query.sort === 'price' ? 'price' : 'name';
  const items = await Product.find({ price: { $lte: maxPrice } }).sort(sortBy);
  res.json(items);
});

router.post('/cart', async (req, res) => {
  const product = await Product.findById(req.body.productId);
  const quantity = parseInt(req.body.quantity, 10);
  const total = product.price * quantity;
  res.json({ total });
});

module.exports = router;
