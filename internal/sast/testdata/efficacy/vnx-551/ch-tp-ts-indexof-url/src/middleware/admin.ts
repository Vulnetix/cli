import { Request, Response, NextFunction } from 'express';

export function adminOnly(req: Request, res: Response, next: NextFunction): void {
  const p: string = req.path;
~>  if (p.indexOf('/admin') === 0 && !res.locals.isAdmin) {
    res.status(403).end();
    return;
  }
  res.locals.route = new URL(p, 'http://localhost').pathname;
  next();
}
