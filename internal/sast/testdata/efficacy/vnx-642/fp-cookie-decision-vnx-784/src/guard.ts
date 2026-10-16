import { Request, Response, NextFunction } from 'express';

export function onlyAdmins(req: Request, res: Response, next: NextFunction) {
  // A decision on a privilege cookie: VNX-784 reports it.
  const flag = req.cookies['isAdmin'];
  if (flag === 'true') {
    return next();
  }
  res.sendStatus(403);
}
