const express = require('express');
const Order = require('./models/order');
const router = express.Router();

router.get('/orders/:id', async (req, res) => {
~>  const order = await Order.findById(req.params.id);
  res.json(order);
});
module.exports = router;
