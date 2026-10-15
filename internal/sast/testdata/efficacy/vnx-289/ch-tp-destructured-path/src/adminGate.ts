import { Request, Response, NextFunction } from 'express';

export function adminGate(req: Request, res: Response, next: NextFunction) {
  const { path } = req;
~>  if (path.startsWith('/admin') && req.user?.role !== 'admin') {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  next();
}
