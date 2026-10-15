const Order = require('../models/order');

async function bigOrders(req, res) {
  const orders = await Order.find({ total: { $gte: Number(req.query.minTotal) } });
  res.json(orders);
}

module.exports = { bigOrders };
