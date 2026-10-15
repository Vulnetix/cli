import { Request, Response, NextFunction } from 'express';

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const { role } = req.cookies;
~>  if (role === 'admin') {
    return next();
  }
  res.status(403).end();
}

export function debugGate(req: Request, res: Response, next: NextFunction) {
~>  if (req.cookies?.isAdmin === 'true') return next();
  res.status(404).end();
}
