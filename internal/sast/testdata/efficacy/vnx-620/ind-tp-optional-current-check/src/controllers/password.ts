import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { UserModel } from '../models/User';

export async function changePassword(req: Request, res: Response) {
  const { oldPassword, newPassword } = req.body;
  const user = await UserModel.findByPk(req.session.userId);
  if (!user) {
    return res.status(404).end();
  }
  if (oldPassword && !(await bcrypt.compare(oldPassword, user.password))) {
    return res.status(401).json({ message: 'Current password is wrong' });
  }
~>  await user.update({ password: await bcrypt.hash(newPassword, 10) });
  return res.status(204).end();
}
