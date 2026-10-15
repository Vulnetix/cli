import { Request, Response } from 'express';

export function slice(req: Request, res: Response) {
  const parts = String(req.query.range).split(':');
~>  const end = Number(parts[1]);
  res.json({ end });
}
