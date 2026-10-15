const express = require('express');
const router = express.Router();
const Order = require('../models/order');

router.post('/checkout', async (req, res) => {
  const order = new Order({ user: req.user.id });
~>  order.total = req.body.total;
~>  const discount = parseFloat(req.query.discount);
  order.total = order.total - discount;
  await order.save();
  res.json(order);
});

module.exports = router;
