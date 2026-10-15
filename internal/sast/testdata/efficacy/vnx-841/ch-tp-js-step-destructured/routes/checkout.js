const Order = require('../models/order');

async function advance(req, res) {
  const { orderId, step } = req.body;
  const order = await Order.findById(orderId);
~>  if (step === 'complete') {
    order.status = 'COMPLETED';
    await order.save();
  }
  res.json(order);
}

module.exports = { advance };
