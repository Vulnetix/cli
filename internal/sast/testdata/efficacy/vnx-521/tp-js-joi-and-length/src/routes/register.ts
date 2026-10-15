import Joi from "joi";
import { body } from "express-validator";
import { z } from "zod";

export const registerSchema = Joi.object({
  email: Joi.string().email().required(),
~>  password: Joi.string().min(4).required(),
});

export const signupRules = [
  body("email").isEmail(),
~>  body("password").isLength({ min: 5 }),
];

export const resetSchema = z.object({
~>  newPassword: z.string().min(6, "too short"),
});

export function validate(user: { password: string }) {
~>  if (user.password.length < 6) {
    throw new Error("weak");
  }
}
