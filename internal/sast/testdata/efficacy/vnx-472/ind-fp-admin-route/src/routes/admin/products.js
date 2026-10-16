const express = require('express');
const Product = require('../../models/product');

const router = express.Router();

router.put('/admin/products/:id', async (req, res) => {
  await Product.update(req.params.id, {
    price: req.body.price,
  });
  res.sendStatus(204);
});

module.exports = router;
