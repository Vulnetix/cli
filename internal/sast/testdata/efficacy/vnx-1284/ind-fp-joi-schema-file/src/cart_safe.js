const Joi = require('joi');
const schema = Joi.object({ productId: Joi.string().required(), quantity: Joi.number().integer().positive().max(100) });

router.post('/cart', async (req, res) => {
  const { error, value } = schema.validate(req.body);
  if (error) return res.sendStatus(400);
  const { productId, quantity } = req.body;
  await CartItem.create({ productId, quantity });
  res.sendStatus(201);
});
