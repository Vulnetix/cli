import Joi from "joi";
import { z } from "zod";
import * as yup from "yup";

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1, "Password is required"),
});

export const signupSchema = Joi.object({
  username: Joi.string().min(3).max(30),
  password: Joi.string().min(12).max(128).required(),
});

export const changePasswordSchema = yup.object({
  currentPassword: yup.string().required(),
  newPassword: yup.string().min(8).max(256).required(),
});

export function tooLong(password: string): boolean {
  return password.length > 64;
}

export function okLength(password: string): boolean {
  if (password.length < 10) {
    return false;
  }
  return true;
}
