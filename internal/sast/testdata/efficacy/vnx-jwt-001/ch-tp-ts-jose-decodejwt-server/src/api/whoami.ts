import { decodeJwt } from 'jose';
import type { Request, Response } from 'express';

export function whoami(req: Request, res: Response) {
  const raw = req.headers.authorization?.slice(7) ?? '';
~>  const claims = decodeJwt(raw);
  res.json({ user: claims.sub, admin: claims.admin === true });
}
