const Joi = require("joi");

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string()
    .required()
~>    .min(6),
});

module.exports = userSchema;
