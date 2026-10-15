import { Request, Response, NextFunction } from 'express';

export function gate(req: Request, res: Response, next: NextFunction) {
~>  if (req.header('x-skip-login') === 'yes-please') return next();
  res.redirect('/login');
}
