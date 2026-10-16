const express = require('express');
const Order = require('../models/order');
const User = require('../models/user');

const router = express.Router();

router.get('/orders/:id', async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, owner: req.user.id });
  if (!order) return res.status(404).end();
  res.json(order);
});

router.get('/docs/:id', async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (doc.ownerId !== req.user.id) return res.status(403).end();
  res.json(doc);
});

router.post('/lookup', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  res.json({ exists: Boolean(user) });
});

router.get('/me', async (req, res) => {
  res.json(await User.findById(req.session.userId));
});

module.exports = router;
