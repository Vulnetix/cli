const express = require('express');
const router = express.Router();

router.get('/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) {
~>    res.sendStatus(404);
  }
  return res.json(order);
});

module.exports = router;
