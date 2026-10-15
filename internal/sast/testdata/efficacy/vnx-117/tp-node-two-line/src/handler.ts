import { Request, Response } from 'express';
import { log } from './log';

export function search(req: Request, res: Response) {
  const term = req.query.term as string;
~>  log.info('search for ' + term);
  res.json([]);
}
