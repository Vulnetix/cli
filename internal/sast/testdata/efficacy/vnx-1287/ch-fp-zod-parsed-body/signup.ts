import { Request, Response } from "express";
import { z } from "zod";

const Signup = z.object({ email: z.string().email() });

export function signup(req: Request, res: Response) {
  const { email } = Signup.parse(req.body);
  res.json({ email: email.toLowerCase() });
}
