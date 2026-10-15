const Joi = require('joi');

const schema = Joi.object({
  productId: Joi.number().integer().required(),
  quantity: Joi.number().integer().positive().max(20).required(),
});

async function add(req, res) {
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).end();
  const { productId, quantity } = req.body;
  await CartItem.create({ productId, quantity });
  res.end();
}

module.exports = { add };
