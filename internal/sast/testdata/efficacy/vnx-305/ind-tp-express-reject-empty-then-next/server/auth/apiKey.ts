import { Request, Response, NextFunction } from 'express';

export function apiKeyGate(req: Request, res: Response, next: NextFunction) {
  const apiKey = req.get('x-api-key');
  if (!apiKey) {
    return res.status(401).send('missing api key');
  }
~>  next();
}
