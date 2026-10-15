import { NextFunction, Request, Response } from 'express';

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const role = req.header('X-Role');
~>  if (role === 'admin' || role === 'owner') {
    return next();
  }
  return res.status(403).send('forbidden');
}
