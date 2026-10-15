import { Request, Response, NextFunction } from 'express';

export function onError(err: Error, req: Request, res: Response, next: NextFunction) {
~>  return res.status(500).json({ error: `Unhandled: ${err.stack}` });
}
