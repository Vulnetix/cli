import type { Request, Response, NextFunction } from 'express';

export function corsHeaders(req: Request, res: Response, next: NextFunction) {
  res.set({
~>    'Access-Control-Allow-Origin': req.get('Origin'),
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  });
  next();
}
