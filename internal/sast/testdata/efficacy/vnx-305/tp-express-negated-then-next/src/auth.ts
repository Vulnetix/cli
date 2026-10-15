import { Request, Response, NextFunction } from 'express';

export function authenticate(req: Request, res: Response, next: NextFunction) {
  const sessionToken = req.cookies.session_token;
  if (!sessionToken) {
    return res.status(401).send('login required');
  }
~>  next();
}
