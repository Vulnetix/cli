import { Request, Response } from 'express';
import { prisma } from '../db';

export async function profile(req: Request, res: Response) {
  const record = await prisma.user.findUnique({ where: { id: req.params.id } });
~>  res.json(record);
}
