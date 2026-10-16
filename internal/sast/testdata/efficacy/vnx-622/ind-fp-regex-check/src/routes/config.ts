import { Request, Response } from 'express';

const CALLBACK_RE = /^[A-Za-z_$][\w$.]*$/;

export function configJsonp(req: Request, res: Response) {
  const cb = String(req.query.cb ?? '');
  if (!CALLBACK_RE.test(cb)) {
    return res.status(400).send('bad callback');
  }
  const body = JSON.stringify({ theme: 'dark' });
  res.type('application/javascript').send(`${cb}(${body})`);
}
