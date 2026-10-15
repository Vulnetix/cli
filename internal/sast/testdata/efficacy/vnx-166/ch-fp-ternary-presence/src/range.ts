import { Request, Response } from 'express';

export function stream(req: Request, res: Response) {
  const range = req.headers.range;
  const parts = String(range).replace(/bytes=/, '').split('-');
  const end = parts[1] ? parseInt(parts[1], 10) : 0;
  res.json({ end });
}
