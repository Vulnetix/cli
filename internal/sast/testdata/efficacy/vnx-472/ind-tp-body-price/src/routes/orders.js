const express = require('express');
const Order = require('../models/order');

const router = express.Router();

router.post('/orders', async (req, res) => {
  const order = await Order.create({
    sku: req.body.sku,
~>    price: req.body.price,
    userId: req.user.id,
  });
  res.status(201).json(order);
});

module.exports = router;
