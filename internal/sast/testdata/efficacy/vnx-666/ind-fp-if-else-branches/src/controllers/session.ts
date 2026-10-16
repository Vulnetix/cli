import { Request, Response } from 'express';
import { verifyPassword } from '../auth';

export async function login(req: Request, res: Response): Promise<void> {
  const ok = await verifyPassword(req.body.username, req.body.password);
  if (ok) {
    res.redirect('/dashboard');
  } else {
    res.status(401).render('login', { error: 'Invalid credentials' });
  }
}

export const handlers = {
  ping: (req: Request, res: Response) => {
    res.sendStatus(204);
  },
  health: (req: Request, res: Response) => {
    res.json({ status: 'ok' });
  },
};
