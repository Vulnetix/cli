const express = require('express');
const router = express.Router();

router.post('/cart', async (req, res) => {
  const { productId, quantity } = req.body;
~>  const item = await CartItem.create({ productId, quantity, userId: req.user.id });
  res.json(item);
});

router.put('/cart/:id', async (req, res) => {
  const item = await CartItem.findByPk(req.params.id);
~>  item.quantity = item.quantity + req.body.quantity;
  await item.save();
  res.json(item);
});

module.exports = router;
