import { Request, Response } from 'express';

export async function register(req: Request, res: Response) {
  const { email, nickname } = req.body;
~>  if (!email.endsWith('@example.com')) {
    return res.status(403).send('corporate addresses only');
  }
  const display = req.query.display;
~>  const shown = display.trim();
  res.json({ email, nickname, shown });
}
