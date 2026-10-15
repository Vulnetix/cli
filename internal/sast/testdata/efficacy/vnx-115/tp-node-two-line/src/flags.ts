import { Request, Response } from 'express';

export function toggle(req: Request, res: Response) {
  const raw = req.query.enabled as string;
~>  const enabled = Boolean(raw);
  const page = req.params.page;
~>  const n = parseInt(page);
  res.json({ enabled, n });
}
