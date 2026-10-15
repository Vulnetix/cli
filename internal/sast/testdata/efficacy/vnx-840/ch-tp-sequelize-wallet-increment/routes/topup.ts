import { Request, Response } from 'express';
import { Card, Wallet } from '../models';

export async function topUp(req: Request, res: Response) {
  const card = await Card.findOne({ where: { id: req.body.cardId, UserId: req.user.id } });
  if (!card) {
    return res.status(402).json({ error: 'no card' });
  }
~>  await Wallet.increment({ balance: req.body.balance }, { where: { UserId: req.user.id } });
  return res.json({ ok: true });
}
