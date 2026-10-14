import type { Request, Response } from 'express';

export function byName(req: Request, res: Response): void {
~>  const pattern = new RegExp(`^${req.params.name}$`, 'i');
  res.json(records.filter((r) => pattern.test(r.name)));
}

export function scan(req: Request, res: Response): void {
  const expr = String(req.query.expr);
~>  const hits = [...corpus.matchAll(new RegExp(expr, 'g'))];
  res.json(hits.length);
}
