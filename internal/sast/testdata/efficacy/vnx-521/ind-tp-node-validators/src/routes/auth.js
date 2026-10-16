const express = require("express");
const { body, validationResult } = require("express-validator");
const Joi = require("joi");
const { z } = require("zod");

const router = express.Router();

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
~>  password: Joi.string().min(6).max(128).required(),
});

const resetSchema = z.object({
  token: z.string().min(10),
~>  newPassword: z.string().min(5, "Password must be at least 5 characters"),
});

router.post(
  "/register",
  body("email").isEmail(),
~>  body("password").isLength({ min: 4 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { error } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    return res.status(201).end();
  }
);

function strongEnough(password) {
~>  if (password.length < 7) {
    return false;
  }
  return /[0-9]/.test(password);
}

module.exports = { router, resetSchema, strongEnough };
