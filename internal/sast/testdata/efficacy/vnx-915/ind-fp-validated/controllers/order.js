const _ = require('lodash');
exports.add = async (req, res) => {
  const data = _.pick(req.body, ['name', 'qty']);
  const o = await Order.create(data);
  const q = await Order.create(schema.parse(req.body));
  // Order.create(req.body)
  const s = "Order.create(req.body)";
  res.json({ o, q, s });
};
