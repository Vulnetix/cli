const Order = require('../models/order');

async function updateOrder(req, res) {
~>  await Order.updateOne({ _id: req.params.id }, { $set: { status: req.body.status } });
  res.sendStatus(204);
}

module.exports = { updateOrder };
