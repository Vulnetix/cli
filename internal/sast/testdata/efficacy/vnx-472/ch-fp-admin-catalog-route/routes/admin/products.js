const express = require('express');
const router = express.Router();
const { requireAdmin } = require('../../middleware/auth');
const Product = require('../../models/product');

router.post('/admin/products', requireAdmin, async (req, res) => {
  const product = await Product.create({
    name: req.body.name,
    price: req.body.price,
  });
  res.status(201).json(product);
});

router.put('/admin/products/:id', requireAdmin, async (req, res) => {
  const price = Number(req.body.price);
  await Product.updateOne({ _id: req.params.id }, { price });
  res.sendStatus(204);
});

module.exports = router;
