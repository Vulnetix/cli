const express = require('express');
const { Order } = require('../models');

const router = express.Router();

router.post('/checkout', async (req, res) => {
~>  const total = req.body.total;
  const order = await Order.create({
    productId: req.body.productId,
~>    price: req.body.price,
    total,
  });
~>  const charged = order.subtotal * (1 - req.query.discount);
  res.json({ id: order.id, charged });
});

router.post('/upgrade', async (req, res) => {
~>  const user = await User.create({ name: req.body.name, role: req.body.role });
  res.json(user);
});

module.exports = router;
