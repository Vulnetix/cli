import { z } from "zod";
import * as yup from "yup";

export const signupSchema = z.object({
  email: z.string().email(),
~>  password: z.string().min(4, { message: "Too short" }),
});

export const resetSchema = yup.object({
~>  newPassword: yup.string().required().min(5),
});
