import type { Request, Response } from 'express';
import { WalletModel } from './models/wallet';

export async function balance(req: Request, res: Response): Promise<void> {
  const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } });
  const card = await prisma.card.findUnique({ where: { id: req.params.id } });
  res.json({ wallet, card });
}

export async function rename(req: Request, res: Response): Promise<void> {
  const user = await UserModel.findByPk(req.params.id);
  const saved = await user.update({ username: req.body.username });
  await UserModel.update({ email: req.body.email }, { where: { id: req.params.id } });
  res.json(saved);
}
