import { Request, Response } from 'express';
import { prisma } from './db';
import { WalletModel } from './models';

export async function getWallet(req: Request, res: Response) {
~>  const wallet = await WalletModel.findOne({ where: { UserId: req.query.UserId } });
  res.json(wallet);
}

export async function listCards(req: Request, res: Response) {
  const cards = await prisma.card.findMany({
~>    where: { userId: req.body.userId },
  });
  res.json(cards);
}
