import type { Request, Response } from 'express';
import { prisma } from '../db';

export async function getMe(req: Request, res: Response) {
  const account = await prisma.user.findUnique({
    where: { id: req.session.userId },
  });
  if (!account) {
    return res.status(401).end();
  }
~>  return res.json(account);
}
