const Joi = require('joi');

const schema = Joi.object({
  password: Joi.string().min(12).required(),
  passwordRepeat: Joi.ref('password'),
});

router.post('/register', (req, res) => {
  const { error } = schema.validate(req.body);
  const rep = req.body.passwordRepeat;
  if (error) return res.status(400).end();
  res.sendStatus(201);
});
