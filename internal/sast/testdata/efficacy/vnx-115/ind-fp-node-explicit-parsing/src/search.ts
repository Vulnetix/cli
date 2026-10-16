import type { Request, Response } from 'express';

export function search(req: Request, res: Response) {
  const limit = parseInt(String(req.query.limit), 10);
  const offset = Number(req.query.offset ?? 0);
  const admin = req.query.admin === 'true';
  const exact = String(req.query.exact).toLowerCase() === 'yes';
  const verbose = Boolean(process.env.VERBOSE);
  const width = Number.parseInt(req.query.width as string, 10);
  res.json({ limit, offset, admin, exact, verbose, width });
}
