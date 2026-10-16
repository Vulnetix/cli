import bcryptjs from 'bcryptjs';
import type { Request, Response } from 'express';

export async function check(req: Request, res: Response): Promise<void> {
  const account = await accounts.byEmail(req.body.email);
~>  const status = bcryptjs.compare(req.body.password, account.hash) ? 200 : 401;
  res.sendStatus(status);
}
