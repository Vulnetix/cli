import { Request, Response } from 'express';

export function afterLogin(req: Request, res: Response) {
  const next = req.query.next || "/";
~>  return res.redirect(next as string);
}

export function afterSso(req: Request, res: Response) {
~>  res.redirect(decodeURIComponent(req.query.return_to as string));
}
