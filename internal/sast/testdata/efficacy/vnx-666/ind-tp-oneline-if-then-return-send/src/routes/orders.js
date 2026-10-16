const express = require('express');
const Order = require('../models/order');

const router = express.Router();

router.put('/orders/:id/cancel', async (req, res) => {
  const order = await Order.findById(req.params.id);
~>  if (!order) res.status(404).send('missing');
  order.status = 'cancelled';
  await order.save();
  return res.json(order);
});

module.exports = router;
