import { Router, Request, Response } from 'express';
import { User } from '../models/user';

export const users = Router();

users.post('/signup', async (req: Request, res: Response) => {
~>  const role = req.body.role;
  const user = await User.create({ email: req.body.email, role });
  res.status(201).json(user);
});
