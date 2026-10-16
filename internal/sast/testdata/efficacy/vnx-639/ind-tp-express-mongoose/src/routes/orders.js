const express = require('express');
const Order = require('../models/order');

const router = express.Router();

router.get('/orders/:id', async (req, res) => {
~>  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).end();
  res.json(order);
});

router.delete('/orders/:id', async (req, res) => {
  const { id } = req.params;
~>  await Order.findByIdAndDelete(id);
  res.status(204).end();
});

module.exports = router;
