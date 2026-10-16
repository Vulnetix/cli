import { Request, Response, NextFunction } from 'express';

export function permissive(req: Request, res: Response, next: NextFunction) {
~>  res.setHeader('Access-Control-Allow-Origin', req.headers.origin as string);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
}
