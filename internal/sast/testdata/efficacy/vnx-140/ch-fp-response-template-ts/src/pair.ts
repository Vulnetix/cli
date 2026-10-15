import { Request, Response } from 'express';

export function pair(req: Request, res: Response) {
  res.write(`${req.query.a},${req.query.b}`);
  res.end();
}
