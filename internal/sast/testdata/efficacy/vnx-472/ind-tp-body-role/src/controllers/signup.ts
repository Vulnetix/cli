import { Request, Response } from 'express';
import { User } from '../models/user';

export async function signup(req: Request, res: Response) {
  const user = new User();
  user.email = req.body.email;
~>  user.role = req.body.role;
  await user.save();
  res.status(201).json({ id: user.id });
}
