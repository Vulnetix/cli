import { Request, Response } from 'express';

export function list(req: Request, res: Response) {
  const limit = parseInt(req.query.limit as string, 10);
  const offset = Number(req.query.offset);
  res.json(db.slice(offset, offset + limit));
}
