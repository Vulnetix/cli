import { Request, Response } from 'express';
import { db } from '../db';

export async function listAccounts(req: Request, res: Response) {
  const accounts = await db.Account.findAll({ where: { active: true } });
~>  return res.status(200).send({ total: accounts.length, items: accounts });
}
