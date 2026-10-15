import { decode, JwtPayload } from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

export function currentUser(req: Request, _res: Response, next: NextFunction) {
~>  const claims = decode(req.cookies.session) as JwtPayload;
  (req as any).userId = claims.sub;
  next();
}
