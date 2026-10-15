const Order = require('../models/order');

exports.cancel = async (req, res) => {
~>  await Order.updateOne(
    { _id: req.body.orderId, owner: req.user.id },
    { $set: { status: 'cancelled' } },
  );
  res.sendStatus(204);
};
