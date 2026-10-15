import { Request, Response } from 'express';
import { User } from './models';

export async function profile(req: Request, res: Response) {
~>  const userId = req.cookies.userId;
  const user = await User.findByPk(userId);
  res.json(user);
}

export async function koaProfile(ctx: any) {
~>  const uid = ctx.cookies.get('uid');
  ctx.body = await User.findOne({ where: { id: uid } });
}
