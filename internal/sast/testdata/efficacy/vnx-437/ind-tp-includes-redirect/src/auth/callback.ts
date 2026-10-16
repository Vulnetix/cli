import { Request, Response } from 'express';

export function finishLogin(req: Request, res: Response) {
  const next = (req.query.next as string) || '/';
  establishSession(req, res);
  if (next.includes('accounts.example.org')) {
~>    return res.redirect(next);
  }
  return res.redirect('/');
}
