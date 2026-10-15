const Order = require('../models/order');

async function listOrders(req, res) {
  const orders = await Order.find({ status: req.query.status, owner: req.user.id });
  const count = await Order.countDocuments({ status: req.query.status });
  res.json({ orders, count });
}

module.exports = { listOrders };
